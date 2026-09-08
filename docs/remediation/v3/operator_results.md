# Operator execution results — metadata-only discovery

Results of operator-run credentialed commands. Codex: read this file before stopping a turn that
requested an operator command. Written by the monitoring session; treat as operator-supplied evidence.

## 2026-09-08T20:37Z — **`V3-DEVENSEMBLE-001` verified live: first EXECUTED cross-lineage ensemble completes on the planted corpus (candidate deepseek, reviewers kimi + glm, 9 requests, all stages observed, 0.068 USD, 100 s). Guarded corpus: 2 of 3 stages; the glm reviewer timed out at 180 s. glm is now the unreliable role-player.**

Timestamp from the clock. Development ledger #3: 63 entries, 59 reconciled, 4 uncertain. **Actual
development spend across ledgers 1.221975476 USD**; phantom uncertain reservations 1.774773176 USD
(the new one is a genuine post-dispatch timeout, correctly uncertain). Cumulative ledger untouched.
Ledger unchanged at 57 entries / `0.68118684` USD. `completed_real_audits` remains `0`.

### 1. Runs (`development ensemble-corpus`, ledger #3, carry mode, truth for scoring only, per-attempt 1.00)

| run id | candidate / reviewer 1 / reviewer 2 (all `=together`) | corpus | status | real cost | wall |
|---|---|---|---|---|---|
| `devensemble-20260908-a-1` | glm (4096) / deepseek (16384) / kimi (16384) | a | `CANDIDATE_INCOMPLETE`: glm shard 1 `length` at 4096 completion, 0 reasoning | 0.0211878 | 91 s |
| `devensemble-20260908-a-2` | **deepseek (65536) / kimi (16384) / glm (16384)** | a | **`OBSERVED_ALL_STAGES`** 3 stages, 6 judgments | 0.06772640 | 100 s |
| `devensemble-20260908-b-1` | deepseek / kimi / glm | b | `REVIEW_INCOMPLETE`: candidate ok, kimi 3/3, **glm review-02 file-01 `TIMEOUT` at 180.0 s**, `UNKNOWN_COST` | 0.05837976 (+0.1877874 uncertain) | 321 s |

Outputs `…/development-audits/ensemble-{a,b}-*-20260908/` with `plan.json`, `benchmark-plan.json`,
`candidate/`, `review-01/`, `review-02/`, `review-0N-plan.json`, `result.json`, `score.json`.

### 2. The executed ensemble result (corpus `a`, run `a-2`)

```
quality_scope COMPLETE_OBSERVATIONS   candidate claims 3   supported 3 / refuted 0 / inconclusive 0
supported_root_recall 1.0   supported_severity_weighted_structural_precision 0.333333 (5/15)
first_attempt_claim_observation_rate 3/3   executed_ensemble_wall_clock_seconds 100.4
stage costs: candidate 0.0125928 | kimi review 0.0430602 | glm review 0.0120734
```

Both reviewers independently supported all three deepseek claims (the planted root, its
consequence, and the misanchored restatement), each with source refs. This is the first time the
`union`/ensemble figure in this build is an **executed** result rather than a recorded-run union,
and it was produced unattended by one command on the development policy. The artifact still says
`lineage_independence: NOT_ESTABLISHED`, correctly.

On corpus `b` the observed stages agree with everything earlier today: candidate 3 advisories,
kimi supports all three as advisories, no invariant claim against the guarded control.

### 3. glm-5.2 on `together` is unreliable in every role except unattended candidate on `a`

Today's glm tally on this route: audits `a`/`b` completed (2 runs); judge over kimi: 2 runaways to
the token cap; ensemble candidate: 1 runaway; ensemble reviewer: 1 success, 1 hang to the 180 s
deadline with no usage reported. deepseek and kimi have had zero such events on `together`. The
operator cannot see inside the failed responses, but the pattern (visible-output generation to the
cap, then a full-deadline hang) is provider/route behaviour, not a property of the corpus. For the
ensemble the operator will prefer deepseek and kimi as reviewers and treat glm as the candidate under
test, or swap glm for a fourth lineage if one becomes admissible.

### 4. Requests

1. Record DEVENSEMBLE's first live evidence: one complete executed ensemble on `a`, a 2-of-3 on `b`
   with the exact failure stage.
2. **Timeout should honour the whole-run deadline budget per stage, or be configurable per role.**
   The reviewer stage hard-stops at 180 s; the run had 1800 s available and the other reviewer
   finished in 22 s. A per-role `--*-timeout-seconds`, or one bounded retry of the timed-out stage
   within the remaining run deadline, would have completed `b-1`.
3. The synthetic negative-control candidate (19:30Z) is now the most valuable small addition:
   fifteen-plus judgments and six ensemble reviews have never produced a `REFUTED`.
4. Standing: `Retry-After` retry, `--reasoning-effort`, judge allowance decoupling.

The operator will rerun `b` once more as-is to see whether the glm reviewer completes (it did on
`a-2`), then move to whatever Codex lands next. The next objective step after that, on the operator's
reading, is the same ensemble over a corpus larger than three files with more than one planted root,
so precision and recall stop being 1-of-1 statistics.

## 2026-09-08T19:30Z — **`V3-DEVJUDGE-001` verified live: three complete cross-lineage judge runs, 15/15 candidate claims `SUPPORTED`, 0 refuted. Two findings: the glm judge runs away on one shard; the judge inherits the candidate's token allowance, which silently couples the judge's cost target to the candidate's.**

Timestamp from the clock. Development ledger #3: 46 entries, 43 reconciled, 3 uncertain
(unchanged). **Actual development spend across ledgers 1.074681516 USD; phantom uncertain
reservations 1.586985776 USD** (unchanged). Cumulative ledger untouched. Ledger unchanged at 57
entries / `0.68118684` USD. `completed_real_audits` remains `0`.

### 1. Judge runs (`development judge-audit`, ledger #3, carry mode, truth supplied for impact only)

| run id | candidate audit | judge=route | tokens / per-attempt | status | judge cost | time |
|---|---|---|---|---|---|---|
| `a-kimi-by-glm-1` | kimi a-3 (6 claims) | glm-5.2=together | 4096 / 0.50 | `JUDGMENT_INCOMPLETE`: file-01 `INCOMPLETE_OUTPUT` (`length`, 4096 completion, 0 reasoning) | 0.0216092 | 33.3 s |
| `a-kimi-by-glm-2` | kimi a-3 | glm-5.2=together | 16384 / 0.50 | `JUDGMENT_INCOMPLETE`: file-01 ok (177 tok), **file-02 `length` at 16384 completion, 0 reasoning** | 0.07724632 | 147.9 s |
| `a-kimi-by-deepseek-1` | kimi a-3 | deepseek=together | 16384 / 0.50 | **`OBSERVED_ALL_JUDGMENTS`** 6/6 | 0.01736064 | 76.7 s |
| `b-kimi-by-deepseek-1` | kimi b-6 (6 advisories) | deepseek=together | 16384 / 0.50 | **`OBSERVED_ALL_JUDGMENTS`** 6/6 | 0.01728012 | 87.3 s |
| `a-deepseek-by-kimi-1` | deepseek a-16 (3 claims) | kimi-k3=together | 16384 / 0.50 | refused pre-dispatch (see §3) | 0 | – |
| `a-deepseek-by-kimi-2` | deepseek a-16 | kimi-k3=together | 65536 / 2.50 | **`OBSERVED_ALL_JUDGMENTS`** 3/3 | 0.0444030 | 30.7 s |

Outputs under `~/.mmaudit/private/development-audits/judge-*`. Every complete run wrote
`plan.json`, `benchmark-plan.json`, `file-0N.json`, `result.json`, `score.json`.

### 2. Verdicts

15 claims judged across three complete runs and three candidate/judge lineage pairings
(kimi→deepseek ×2, deepseek→kimi): **15 `SUPPORTED`, 0 `REFUTED`, 0 `INCONCLUSIVE`**. Each decision
carries source refs to the exact lines. Reading them, every supported claim is a true statement about
the fixture, including the six guarded-corpus advisories and deepseek's misanchored root claim
(`file-02:01`, judged on substance: "RoutePolicy.setGateway … onlyAdministrator", `SUPPORTED`).
`supported_root_recall 1.0` on both planted judgments; `supported_severity_weighted_structural_precision`
equals the candidate's (0.19 kimi, 0.33 deepseek) because nothing was removed.

**What this does not show:** the judge has never been observed to refute. All 15 inputs were
plausibly correct, so 15/15 may be right, but there is no live negative control. The operator has
no natural false claim to feed it; a deliberately wrong synthetic candidate (e.g. a fabricated
"reentrancy in `_move`") would be the honest test and belongs in the DEVJUDGE record as a gap
until run.

### 3. Findings

1. **glm-5.2 as judge runs away.** On the same route where it audits in 45–500 tokens, as a judge
   it hit `finish_reason length` at 4096 and again at 16384 completion tokens with
   `reasoning_tokens 0` on shard file-02 (kimi's two UnitRouter claims). That is visible-output
   generation to the cap, i.e. a loop on the judge schema, at 0.076 USD per occurrence. deepseek
   and kimi judged the same shard in 479 and 406 tokens. Not diagnosed further; the response is
   not retained. Worth a bounded look at what the judge schema/prompt does differently from the
   audit one.
2. **Judge allowance is forced equal to the candidate's.** `DevelopmentJudgmentPlan` rejects a
   shard unless `estimate.maximum_completion_tokens == self.maximum_completion_tokens` **and**
   `within_estimated_budget`, and the plan takes the tokens from the candidate. So judging a
   65536-token deepseek candidate with kimi requires a per-attempt target ≥ 2.06 USD even though
   the judge answered in ~400 tokens. The CLI refusal text ("invalid candidate, source, identity,
   consent, cumulative accounting or output custody") does not name this. Suggest decoupling the
   judge allowance (its output is a bounded decision list) or at least naming the check in the
   refusal.
3. Verified good: cross-lineage pairing is enforced only by operator choice (the artifact says
   `lineage_independence: NOT_ESTABLISHED`, correctly); truth is not sent to the judge; carry mode
   worked throughout; decisions are source-anchored.

### 4. Requests

1. Record DEVJUDGE's first live evidence as above (three complete pairings, 15/15 supported, no
   refutation observed).
2. Add a **synthetic negative-control candidate** (committed, non-deployable, with one deliberately
   false invariant claim) so the operator can demonstrate a `REFUTED` verdict live for a few cents.
3. Decouple or name the judge token-allowance coupling (§3.2).
4. Bounded look at the glm judge runaway (§3.1); `--reasoning-effort` and the `Retry-After` retry
   remain open from earlier entries.
5. With candidate, scorer, comparator and judge all verified on the development policy, the
   operator's reading of the next objective-relevant step is unchanged from 17:38Z: the
   **executed ensemble** (candidate + two cross-lineage judges in one run, one `score.json`, union
   as an executed result), then the same on a corpus larger than three files.

## 2026-09-08T17:38Z — **THREE LINEAGES MEASURED on the same frozen pair. deepseek-v4-pro completes on `together` (fireworks rate-limits back-to-back shards). Three-model comparison artifacts written. One scorer nuance: a correct root reported with the wrong primary anchor counts as `UNMATCHED_INVARIANT`.**

Timestamp from the clock. Development ledger #3: 34 entries, 31 reconciled, 3 `uncertain_accounted`
(three fireworks 429s). **Actual development spend across ledgers 0.896782236 USD; phantom
uncertain reservations 1.586985776 USD.** Cumulative ledger untouched. Ledger unchanged at 57
entries / `0.68118684` USD. `completed_real_audits` remains `0`.

### 1. Runs since 17:33Z (all ledger #3, carry mode, 65536 tokens, per-attempt 1.00)

| run id | model=route | corpus | status | cost | time |
|---|---|---|---|---|---|
| `a-15-deepseek` | deepseek=fireworks | a | `SHARD_INCOMPLETE`: file-01 ok (2855 tok, 2546 reasoning), **file-02 HTTP 429** | 0.011462572 real | 32.6 s |
| `a-16-deepseek-together` | deepseek=**together** | a | **`OBSERVED_ALL_SHARDS`** | 0.01241856 | 34.5 s |
| `b-17-deepseek-together` | deepseek=together | b | **`OBSERVED_ALL_SHARDS`** | 0.01357884 | 52.1 s |

fireworks returned 429 on the 2nd or 3rd consecutive shard in three of three multi-shard attempts;
`together` served all six shards first time. Discovery: `devtrial-deepseek-v4-pro-together-20260908-d8`
(operational, ZDR, native schema, efforts `[low, high, max]`, prompt 1.32e-6 / completion 3.96e-6).
Telemetry difference worth recording: on `together` deepseek reports `reasoning_tokens: 0` and
completes in 45–1014 completion tokens; on fireworks the same model at the same `effort: high`
reported 2.5–4.7k reasoning tokens. Same model id, materially different reasoning behaviour by
provider; the operator has no basis to say which is "correct".

### 2. Three-model comparison (`compare-scores`, provider-free)

`compare-a-three-models-20260908.json` (sha `32ff8b3f…`) and `compare-b-three-models-20260908.json`
(sha `10072fe0…`) under `~/.mmaudit/private/development-audits/`. Both `COMPLETE_OBSERVATIONS`;
self-labels unchanged (descriptive, lineage/parity not established, superiority not evaluated).

Planted corpus `a`:

| model=route | tokens | root recall | sw structural precision | claims / dup / adv / unmatched | cost | time |
|---|---|---|---|---|---|---|
| `z-ai/glm-5.2=together` | 4096 | 1.0 | **0.50** | 2 / 1 / 0 / 0 | 0.01205044 | 19.6 s |
| `deepseek-v4-pro-0813=together` | 65536 | 1.0 | 0.33 | 3 / 1 / 0 / **1** | 0.01241856 | 34.5 s |
| `moonshotai/kimi-k3=together` | 4096 | 1.0 | 0.19 | 6 / 2 / 3 / 0 | 0.0849096 | 77.9 s |

Guarded corpus `b`:

| model=route | invariant claims | guarded-control claims | advisories | first-attempt completion | cost | time |
|---|---|---|---|---|---|---|
| glm-5.2 | 0 | 0 | 0 | 1.0 | 0.00918728 | 6.5 s |
| deepseek-v4-pro | 0 | 0 | 5 (all UnitStore, all `low`) | 1.0 | 0.01357884 | 52.1 s |
| kimi-k3 | 0 | 0 | 6 | 1.0 | 0.1043244 | 71.5 s |

Union row on `a`: one root, shared by all three. No model produced a guarded-control claim on `b`.
All three lineages find the planted defect at the exact span; none claims the guarded invariant is
broken. They differ in noise and cost. On this corpus pair, in this order: glm, deepseek, kimi.

### 3. Scorer nuance, for the DEVBENCH record

deepseek's `UNMATCHED_INVARIANT` (`file-02:01`, weight 5) is **the planted root**, correctly
described ("RoutePolicy.setGateway is declared without the onlyAdministrator modifier…"), with
`root_cause_ref` `RoutePolicy.sol:40–46` — but its primary anchor is also `40–46` on a UnitRouter
shard, outside the manifest's UnitRouter claim sites. The scorer is right by its rules (primary
must be in the primary file), and the operator agrees the rule should stay. But lumping this with
"claimed something not planted" hides a real distinction. Suggest a third disposition,
e.g. `MISANCHORED_CONSEQUENCE` (root matches, primary anchor invalid), kept in all-claim
denominators but reported separately from unmatched claims that name a different defect.

### 4. Requests

1. Record the three-lineage measurement under DEVBENCH/DEVCOMPARE. Inputs are all committed
   corpora and frozen discovery files; every number above is recomputable from `score.json`.
2. `MISANCHORED_CONSEQUENCE` (or equivalent) disposition — small, scoring-only.
3. `Retry-After` single in-run retry (fireworks is now the concrete case, three of three).
4. `--reasoning-effort` (deepseek at `high` needs ≥16k headroom on fireworks; on together it
   apparently does not reason at all — the effort should be recorded per plan so this is visible).
5. Now that three lineages have complete pairs, the next capability toward the objective is the
   **executed ensemble** over these routes (candidate + cross-lineage judges on the development
   policy, scored by the same truth), so that `union` becomes an executed result rather than a
   recorded-run union. The operator will run it on the same corpora and ledger.

## 2026-09-08T17:33Z — **`V3-DEVCARRY-001` and `V3-DEVTELEMETRY-001` verified live. Ledger #3 reopened under carry mode. deepseek truncation explained by telemetry: at a 4096 allowance it spends all 4096 tokens reasoning; at 65536 it finishes in 3–5k and finds the root. A mid-run 429 now leaves a 0.556 USD phantom reservation instead of a dead ledger.**

Timestamp from the clock. Development ledger #3: 26 entries, 24 reconciled, 2 `uncertain_accounted`
(0.069107368 + 0.555709440 reserved). **Actual development spend across ledgers 0.859322264 USD;
phantom uncertain reservations 1.031273608 USD.** Cumulative ledger untouched. Ledger unchanged
at 57 entries / `0.68118684` USD. `completed_real_audits` remains `0`.

### 1. DEVCARRY verified ($0 then live)

On a copy of locked ledger #3: default policy → `CostBudgetExceededError … requires all prior
provider costs to be settled`; `uncertain_cost_policy: CARRY_RESERVED_ESTIMATE` → reserved and
released. Live: `--carry-uncertain-estimates` on the real ledger #3 accepted three runs below. The
uncertain entries stay byte-exact and fully counted. Ledgers #1 and #2 are therefore also usable
again with the flag; the operator will consolidate on #3.

### 2. DEVTELEMETRY verified with real numbers; deepseek truncation explained

| run | allowance | shard 1 telemetry | result |
|---|---|---|---|
| `a-12-deepseek` | 4096 | `finish_reason length`, prompt 3534, completion **4096**, reasoning **4096**, `CONSISTENT` | `INCOMPLETE_OUTPUT`, 0.02088504 |
| `a-13-deepseek` | 65536 @ per-attempt 0.50 | refused pre-dispatch: estimate exceeds target (policy working) | no charge |
| `a-14-deepseek` | 65536 @ per-attempt 1.00 | file-01 `stop`, completion 2903 / reasoning 2607; file-02 `stop`, 4977 / 4651; **file-03 HTTP 429** | 2/3 observed, real charges 0.011652652 + 0.0243738 |

So `deepseek/deepseek-v4-pro-0813` at `reasoning.effort: high` on fireworks consumes the entire
completion allowance as reasoning when the allowance is small, producing zero visible output; with
headroom it reasons 2.6–4.7k tokens and answers. The two earlier "truncations" were the same
behaviour. Observed shards: `MATCHED_ROOT` on RoutePolicy (the planted defect) plus one
`DUPLICATE_OR_CONSEQUENCE`, no advisories — the same shape as glm's output, at glm-like cost per
shard.

### 3. The 429 pattern on fireworks

Three fireworks 429s today (`a-11` first request; `a-14` third consecutive request; both within
seconds of a prior request). Under carry mode the `a-14` one leaves `uncertain_accounted` at the
full 65536-token reservation (0.555709440) and the score's `accounted_cost_usd` reports
0.591735892 against 0.036026452 real. The scorer already carries `reported_actual_cost_usd`
separately, so nothing is misreported, but the phantom will dominate any cost column until settled.

### 4. Requests, in current priority

1. **`Retry-After`-bounded single in-run retry on 429** (first raised 13:18Z). It would have
   completed `a-14` and is now the difference between a 3-shard run finishing and not on this
   provider. Please keep first-attempt completion scored on the first attempt.
2. **`--reasoning-effort`** on the development commands (15:12Z req. 2). deepseek needs `high`
   with ≥ 16k headroom or a lower effort; kimi and glm are fine at `high`/4096. Record the effort
   in `plan.json`.
3. Settle attestation for `uncertain_accounted` entries remains wanted for the cumulative ledger's
   long-term hygiene, but is no longer blocking development.

The operator will retry deepseek on both corpora once request 1 lands, spacing requests to avoid
the provider limit in the meantime is not something the operator can do inside a single run.

## 2026-09-08T16:26Z — **THIRD LEDGER RETIRED BY A ZERO-COST 429. `V3-DEVTELEMETRY-001` verified on that response (all fields `NOT_REPORTED`, correctly). Paid runs paused until the settle / no-generation fix lands.**

Timestamp from the clock. Development ledger #3: 22 entries, 21 reconciled, **1 `uncertain_accounted`
at 0.069107368 reserved, actual `null`** → locked. Actual development spend across ledgers
unchanged at 0.802410772 USD; phantom uncertain reservations now 0.475564168 USD across three
retired ledgers. Cumulative ledger untouched. Ledger unchanged at 57 entries / `0.68118684` USD.
`completed_real_audits` remains `0`.

### 1. Run

`devbench-20260908-a-11-deepseek` (deepseek-v4-pro=fireworks, corpus a, 4096 tokens, ledger #3),
intended to read the newly retained token counts behind the two `INCOMPLETE_OUTPUT` truncations.
fireworks returned **HTTP 429 in 0.8 s** on shard 1 → `[HTTP_ERROR, UNKNOWN_COST]`,
`uncertain_accounted`, run `SHARD_INCOMPLETE` 0/3. Output
`…/unit-ledger-a-v1-scored11-deepseek-fireworks/`.

### 2. DEVTELEMETRY verified for the error path

`completion_telemetry` is present on the rejected shard with `interpretation:
REPORTED_METADATA_NOT_VERIFIED_USAGE`, `finish_reason_state: NOT_REPORTED`, all four token fields
`{state: NOT_REPORTED, value: null}`, `token_sum_consistency: NOT_OBSERVED`. That is the correct
rendering of a 429 error body. The truncation question for deepseek remains open because the
provider rate-limited before a generation; the operator will not probe again until §3 is fixed.

### 3. This is now the single most damaging defect in the product

Three 429s today, each costing nothing, have retired three ledgers holding the entire day's
reconciled history (0.80 USD of real, settled charges), because `reconcile(reservation,
actual_cost_usd=None)` on an error body permanently blocks every later reservation and nothing can
close the entry. Consequences observed today: the operator cannot rerun a variant on the same
ledger after any provider flap; cumulative accounting is fragmented across files; and the more
flaky the route, the faster the ledger dies. The restated request, in order of preference:

1. **No-generation classification** (13:12Z req. 2): non-200 with a parseable `error` body, no
   `usage`, no `id` → `settled_no_generation` (accounted at the reserved maximum if you want to stay
   conservative toward the cap, but **not** a blocking unsettled liability). Regression: a 429 must
   not block the next reservation.
2. **Operator settle command** (05:24Z / 13:12Z req. 1) for the existing three entries, with the
   attestation retained.
3. `Retry-After`-bounded single in-run retry on 429 (13:18Z req. 2).

Until 1 or 2 lands the operator will run no further paid development commands; there is no
sensible fourth ledger. Everything else (comparator, schema alignment, telemetry) is verified and
in use.

## 2026-09-08T15:43Z — `V3-DEVCOMPARE-001` verified: `compare-scores` run on both corpora, provider-free. Two comparison artifacts on disk.

Timestamp from the clock. No provider call, no ledger access. Development ledgers unchanged from
15:12Z (total actual 0.802410772 USD). Cumulative ledger untouched. Ledger unchanged at 57
entries / `0.68118684` USD. `completed_real_audits` remains `0`.

```
compare-scores --score-file a-3(kimi) --score-file a-9(glm)  -> compare-a-kimi-vs-glm-20260908.json  sha 05804440…  COMPLETE_OBSERVATIONS
compare-scores --score-file b-6(kimi) --score-file b-10(glm) -> compare-b-kimi-vs-glm-20260908.json  sha fc92081c…  COMPLETE_OBSERVATIONS
```

Both under `~/.mmaudit/private/development-audits/`. Per-run rows carry the score SHA, model, route,
completion allowance, and shared/unique roots; the union row reports one shared root on `a`, none on
`b`, summed cost 0.09696004 / 0.11351168, `first_attempt_shard_completion 6/6` on each. The
artifact self-labels `DESCRIPTIVE_RECORDED_RUNS_NOT_A_CONTROLLED_EXPERIMENT`,
`OBSERVED_ROOT_UNION_NOT_AN_EXECUTED_ENSEMBLE`, `lineage_independence: NOT_ESTABLISHED`,
`request_and_budget_parity: NOT_ESTABLISHED`, `superiority: NOT_EVALUATED`. The operator agrees with
every one of those labels for this input set and has no correction.

Observation only: the comparator does not consult the public-lineage bundle that the AUTHRUNNER
path already sealed for these two lineages (kimi and glm were CONFIRMED distinct roots on
2026-08-24). Binding that evidence would let `lineage_independence` become `ESTABLISHED` for exactly
these pairs without a human claim. Not requested now; noted for the ensemble ticket.

Standing requests unchanged: token-count retention on `INCOMPLETE_OUTPUT`, `--reasoning-effort`,
enumeration duplicate handling, ledger settle path. The operator has nothing further to run until
one of them lands or Codex names the next capability.

## 2026-09-08T15:12Z — **SECOND MODEL MEASURED: `z-ai/glm-5.2=together` completes both corpora first time; recall 1.0, structural precision 0.5, zero claims on the guarded corpus, ~10x cheaper and faster than kimi-k3. deepseek-v4-pro on fireworks truncates twice with no retained token evidence.**

Timestamp from the clock. Development ledger #3: 21 entries, all reconciled, actual 0.541770772.
Ledgers #1/#2 unchanged (retired). **Total actual development spend 0.802410772 USD; phantom
uncertain reservations 0.4064568 USD.** Cumulative ledger untouched. Ledger unchanged at 57
entries / `0.68118684` USD. `completed_real_audits` remains `0`.

### 1. Route selection ($0)

`list-endpoints` fails closed for both `deepseek/deepseek-v4-pro-0813` and `z-ai/glm-5.2` with
`endpoint inventory contains duplicate exact routes`. A direct read of OpenRouter's per-model
endpoint list shows the cause is upstream: the provider inventory literally lists `baseten/fp4`
twice for deepseek and `baseten/fp8` + `baseten/fast` twice each for glm. The enumerator is
correct to refuse ambiguity, but it now refuses two of the three lineages the product has ever
used; request 3 below. `discover` on an explicit route still works. glm's former judge route
`sail-research/fp8` no longer exists. Frozen: `devtrial-glm-5-2-together-20260908-d7`
(operational, ZDR, native JSON schema, model efforts `[high, xhigh]`, prompt 1.4e-6 /
completion 4.4e-6) and `devtrial-deepseek-v4-pro-fireworks-20260908-d6` (operational, ZDR, native
schema, efforts `[low, high, max]`, prompt 1.32e-6 / completion 3.96e-6).

### 2. Runs

| run id | model=route | corpus | status | shards | cost | time |
|---|---|---|---|---|---|---|
| `devbench-20260908-a-7-deepseek` | deepseek-v4-pro=fireworks | a | `SHARD_INCOMPLETE` file-01 `INCOMPLETE_OUTPUT` (4096 tok) | 0/3 | 0.02088504 | 54.9 s |
| `devbench-20260908-a-8-deepseek` | deepseek-v4-pro=fireworks | a | `SHARD_INCOMPLETE` file-01 `INCOMPLETE_OUTPUT` (16384 tok) | 0/3 | 0.065037412 | 127.7 s |
| `devbench-20260908-a-9-glm` | glm-5.2=together | a | **`OBSERVED_ALL_SHARDS`** | 3/3 | 0.01205044 | 19.6 s |
| `devbench-20260908-b-10-glm` | glm-5.2=together | b | **`OBSERVED_ALL_SHARDS`** | 3/3 | 0.00918728 | 6.5 s |

Outputs: `…/development-audits/unit-ledger-a-v1-scored{7,8}-deepseek-fireworks/`,
`…/unit-ledger-a-v1-scored9-glm-together/`, `…/unit-ledger-b-v1-scored10-glm-together/`.

### 3. Two-model comparison on the same frozen corpora (both `COMPLETE_OBSERVATIONS`)

| metric | kimi-k3=together (a-3 / b-6) | glm-5.2=together (a-9 / b-10) |
|---|---|---|
| `unique_root_recall` | 1.0 | 1.0 |
| `severity_weighted_root_recall` | 1.0 | 1.0 |
| `all_claim_unique_root_fraction` | 0.166667 (1/6) | **0.5** (1/2) |
| `severity_weighted_structural_precision` | 0.192308 (5/26) | **0.5** (5/10) |
| planted: claims / duplicates / advisories | 6 / 2 / 3 | 2 / 1 / 0 |
| guarded: invariant claims / advisories | 0 / 6 | **0 / 0** |
| `first_attempt_shard_completion` (a, b) | 1.0, 1.0 (b needed 4 attempts pre-SCHALIGN) | 1.0, 1.0 |
| cost (a + b) | 0.0849096 + 0.1043244 = 0.1892340 | 0.01205044 + 0.00918728 = **0.02123772** |
| wall clock (a + b) | 77.9 + 71.5 s | **19.6 + 6.5 s** |

glm's planted output: `file-01` high "setGateway lacks administrator authorization" lines 40–46
(matched root) and `file-03` the same title and span anchored to UnitStore (duplicate). Nothing
else. On the guarded corpus it returned no findings at all in three shards. kimi finds the same
root, then adds a consequence restatement per shard and several advisories.

Operator reading, not validation: on this two-root, six-shard development pair, glm-5.2 is at
least as good on recall, strictly better on structural precision, and roughly 9x cheaper and 6x
faster. That is the first empirical fact this build has produced about model choice. It is one
tiny public corpus; it says nothing about coverage on real code. But it is exactly the shape of
evidence the 2026-09-06 priority asked for, and it is now reproducible from committed inputs.

### 4. deepseek: cannot be measured yet; diagnosability gap

Both attempts consumed the entire completion allowance (cost ⇔ ~4.1k then ~16.4k completion
tokens at fireworks' price) and were rejected as `INCOMPLETE_OUTPUT`. The shard record retains
**no `finish_reason` and no token counts**, so the operator cannot tell whether the model is
reasoning past the cap at `effort: high` (the dev path hard-codes `high`), looping on the strict
schema, or something else. August smoke evidence shows this model at ~1.2–1.9k completion tokens
with reasoning ≈ completion on a 234-token prompt, so 16k+ on a 3k-token prompt is anomalous. The
operator stopped at $0.086 rather than spend $0.26 blind.

### 5. Requests

1. **`INCOMPLETE_OUTPUT` (and every non-structured rejection) must retain `finish_reason`,
   `prompt_tokens`, `completion_tokens`, `reasoning_tokens` when the provider reports them.**
   DEVDECODE covered the structured-output stage; this stage is still blind.
2. Consider exposing `--reasoning-effort {low,medium,high}` on the development commands, default
   `high` unchanged, so a model that overruns at `high` can be measured at a lower effort with the
   effort recorded in `plan.json`.
3. **Enumeration:** when OpenRouter lists an exact tag twice, retain the duplicate as evidence and
   continue with the deduplicated set (identical records) or mark only that tag ambiguous, rather
   than refusing the whole model. Two of three lineages are currently unenumerable.
4. Bound a **provider-free comparator** over N `score.json` files (per-model rows for the metrics
   in §3 plus a union-of-roots row and cost/time), since the two inputs now exist on disk. The
   operator will supply the paths.
5. Ledger settle / no-generation classification (13:12Z) remains open.

## 2026-09-08T15:02Z — **`V3-DEVSCHALIGN-001` verified live: guarded variant `COMPLETE_OBSERVATIONS` on the first attempt. The planted/guarded measured baseline pair now exists. Accounting corrected.**

Timestamp from the clock. **Accounting correction:** Codex was right; the 13:18Z and 14:28Z ledger
#3 figures were read mid-run. Exact now: ledger #1 10 entries (9 reconciled, actual 0.2606400,
uncertain reserved 0.2032284); ledger #2 1 entry (uncertain 0.2032284); ledger #3 13 entries, all
reconciled, actual 0.4346106. **Total actual development spend 0.6952506 USD; total phantom
uncertain reservations 0.4064568 USD.** Cumulative ledger untouched. Ledger unchanged at 57
entries / `0.68118684` USD. `completed_real_audits` remains `0`.

### 1. Run

`devbench-20260908-b-6`, guarded `unit-ledger-b-v1`, `moonshotai/kimi-k3=together`, ledger #3,
output `…/unit-ledger-b-v1-scored6-together/`, launched on the DEVSCHALIGN tree (before Codex's
`b00ca54` commit, same source).

```
status OBSERVED_ALL_SHARDS   shards 3/3   cost 0.1043244   elapsed 71.5 s
file-01 0.0303252 | file-02 0.0327102 | file-03 0.0412890   all HTTP 200, no diagnostics
```

### 2. Guarded variant `b` — first complete score

| metric | value | num/den |
|---|---|---|
| `quality_scope` | `COMPLETE_OBSERVATIONS` | |
| `invariant_claim_count` / `guarded_control_claim_count` / `unmatched_invariant_claim_count` | **0 / 0 / 0** | |
| `advisory_claim_count` | 6 | |
| `first_attempt_shard_completion` | **1.0** | 3/3 |
| `all_claim_unique_root_fraction`, `severity_weighted_structural_precision` | 0.0 | 0/6 (no planted roots; expected) |

The model never claims the guarded invariant is violated, across three shards and six findings, all
correctly typed as advisories. Combined with the 13:18Z planted result (recall 1.0), the corpus pair
discriminates cleanly at the invariant level. Precision on the planted variant (0.19 structural) is
the honest number to carry forward; it is dominated by per-shard restatement of one root.

### 3. What the alignment changed, observed from the run

Three prior guarded attempts each lost one shard to `ADVISORY_FIELD_MUST_BE_NULL`. After
DEVSCHALIGN the same route returned three conforming shards first time. The operator did not
independently re-derive the request schema (the raw Pydantic view still shows nullable fields; the
per-kind choice is applied at request construction, `development_review.py:158-164`), so the
evidence is the run outcome plus Codex's tests, not an operator schema audit.

### 4. Standing requests, reprioritized

1. **Ledger settle / no-generation classification (13:12Z)** — now the only structural defect
   exposed today that is still open. Two ledgers retired by zero-cost 429s.
2. **Bounded in-run second attempt for 429 / `INVALID_RESPONSE`** — lower priority now that the
   schema cause is removed; still needed for provider flaps like this morning's modal 429s.
3. Please record `V3-DEVTRIAL-001` guarded evidence and the DEVBENCH baseline pair as evidenced.

### 5. Proposed next capability (for Codex to bound; the operator will run it)

The 2026-09-06 priority was: real single-model baseline, **then measure the ensemble against it**.
The baseline pair exists. The smallest next step that produces an ensemble comparison is: run the
identical scored development path with a **second, lineage-independent model** on the same two
corpora (candidates from the retired triple: `z-ai/glm-5.2` or `deepseek/deepseek-v4-pro-0813`
on any ZDR route with native JSON schema; enumeration for glm currently fails closed on provider
duplicates, deepseek's parasail route is tombstoned but its other routes are not), and emit a
comparison artifact over the two `score.json` files: per-model recall / structural precision /
first-attempt completion / cost / time, plus a union-of-roots row. No new transport is needed; the
comparison is provider-free. If Codex prefers, the operator can produce the second model's
`score.json` first with the existing command and Codex can build the comparator against real
inputs.

## 2026-09-08T14:28Z — **`V3-DEVDECODE-001` verified live: the guarded-variant shard failures are `ADVISORY_FIELD_MUST_BE_NULL` on `root_cause_ref`. The model cannot know that rule: the strict schema has no conditional on `kind` and the prompt does not state it.**

Timestamp from the clock. Development ledger #3: 11 entries, all `reconciled` (correction: the
13:18Z entry said 5; it was 8 at that moment, the b-4 run had already settled). Actual development
spend across the three ledgers `0.4875360` USD. Cumulative ledger untouched. Ledger unchanged at
57 entries / `0.68118684` USD. `completed_real_audits` remains `0`.

### 1. Run

`devbench-20260908-b-5`, guarded `unit-ledger-b-v1`, route `moonshotai/kimi-k3=together`, ledger #3,
output `…/unit-ledger-b-v1-scored5-together/`. Result `SHARD_INCOMPLETE` at `file-02` again:
`file-01 OBSERVED` (0.0319662), `file-02 INCOMPLETE [INVALID_RESPONSE]` HTTP 200 (0.0425928,
reconciled). 105.6 s, 0.0745590 USD. Observed shard: 4 advisories, 0 invariant claims, 0 guarded
control claims. Third consecutive guarded attempt to lose one shard this way (b-3 file-02, b-4
file-03, b-5 file-02).

### 2. Retained reason (new, from DEVDECODE)

```
rejection_evidence.stage:              STRUCTURED_OUTPUT
rejection_evidence.structured_failure: SCHEMA_VALIDATION_FAILED
rejection_evidence.schema_issues:      [{constraint: ADVISORY_FIELD_MUST_BE_NULL,
                                         field: root_cause_ref, finding_index: 2}]
```

One advisory (finding 2 of the shard) carried a `root_cause_ref`, and the strict post-decoder rejected
the entire shard. The diagnosability request is closed; this is exactly what was needed.

### 3. Why the model does this ($0, from the shipped schema and prompt)

`strict_json_schema(DevelopmentScoredReviewResponse)` presents `kind` as an enum
`[invariant_violation, advisory]` and, independently, `root_cause_ref`, `vulnerability_class` and
`violated_invariant` as plain `anyOf[X, null]`. There is **no `if`/`oneOf`/`allOf` conditional tying
those fields to `kind`**, and the system prompt contains no sentence about advisories requiring
nulls. So the provider-side schema admits an advisory with a `root_cause_ref`, the model reasonably
emits one (an advisory that points at the planted root is a sensible thing to say), and the
client-side rule then discards ~1 shard in 3 on the guarded corpus. Note the failure only appears on
the guarded variant, where nearly every finding is an advisory; on the planted variant most findings
are invariant claims and the rule is rarely exercised.

### 4. Requests (bounded; whichever is cheapest first)

1. **Express the rule where the model can see it.** Preferred: a `oneOf` on `kind` in the strict
   schema (advisory branch with the three fields typed `null`; violation branch with them required).
   If OpenRouter strict mode rejects conditionals for this route, then (a) state the rule in the
   system prompt and (b) make the client-side decoder **tolerant for advisories**: drop or retain-as-
   annotation any `root_cause_ref`/class/invariant on an advisory rather than rejecting the shard.
   Keep the rule strict for `invariant_violation`, where those fields carry scoring weight. An
   advisory pointing at a root is harmless to the scorer (it already has `ADVISORY_AT_PLANTED_SITE`).
2. The bounded in-run second attempt (13:18Z request 2) still matters for 429s and genuine schema
   failures, but request 1 alone would likely have completed all three guarded runs today.
3. The ledger settle path and no-generation error classification (13:12Z) remain the top structural
   blocker; ledgers #1 and #2 are still retired with 0.4064568 USD of phantom reservations.

The operator will rerun the guarded variant once request 1 lands. `V3-DEVTRIAL-001` guarded
evidence is otherwise complete on every observed shard: no invariant claim was ever made against the
guarded control.

## 2026-09-08T13:18Z — **FIRST MEASURED BASELINE (`V3-DEVBENCH-001`, `score.json`): planted variant recall 1.0, structural precision 0.19; guarded variant 0 invariant claims but 1-in-3 shards `INVALID_RESPONSE` on two attempts. Route switched to `together` after modal 429s.**

Timestamp from the clock. Development ledgers: #1 10 entries (9 reconciled / 1 uncertain), #2 1 entry
(uncertain), #3 5 entries (all reconciled). Actual development spend across ledgers `0.4129770` USD;
uncertain reservations `0.4064568` USD (two 429s, no charge reported). Cumulative ledger untouched.
Ledger unchanged at 57 entries / `0.68118684` USD. `completed_real_audits` remains `0`.

### 1. Route change ($0 evidence)

After the second 429 on `modal/mxfp4` (see 13:12Z), `list-endpoints --model moonshotai/kimi-k3` began
failing closed with `per-model and ZDR endpoint diagnostic facts are inconsistent`, and the key's own
status (`/auth/key`: limit 200, remaining 199.74, not free tier, daily usage 0.26064 = the day's
reconciled charges) showed no key-level limit. Fresh discovery of `moonshotai/kimi-k3=together`
(`devtrial-kimi-k3-together-20260908-d3`): operational, ZDR, native JSON schema, model-level
efforts `[low,high,max]`, identical prices. Scored runs below use that route on ledger #3.

### 2. Scored runs (`--truth-manifest`, response schema 2.0)

| run id | corpus | route | status | shards | cost | time |
|---|---|---|---|---|---|---|
| `devbench-20260908-a-1` | a | modal | `SHARD_INCOMPLETE` (429) | 0/3 | 0 reported | 1.2 s |
| `devbench-20260908-a-2` | a | modal | `SHARD_INCOMPLETE` (429) | 0/3 | 0 reported | 1.0 s |
| `devbench-20260908-a-3` | a | together | **`OBSERVED_ALL_SHARDS`** | 3/3 | 0.0849096 | 77.9 s |
| `devbench-20260908-b-3` | b | together | `SHARD_INCOMPLETE` (file-02 `INVALID_RESPONSE`, HTTP 200) | 1/3 | 0.0674274 | 88.2 s |
| `devbench-20260908-b-4` | b | together | `SHARD_INCOMPLETE` (file-03 `INVALID_RESPONSE`, HTTP 200) | 2/3 | 0.1033902 | 86.1 s |

Outputs under `~/.mmaudit/private/development-audits/unit-ledger-{a,b}-v1-scored{3,4}-together/`,
each with `plan.json`, `benchmark-plan.json`, `file-0N.json`, `result.json`, `score.json`.

### 3. First measured numbers — variant `a` (planted), `quality_scope: COMPLETE_OBSERVATIONS`

| metric | value | num/den |
|---|---|---|
| `unique_root_recall` | **1.0** | 1/1 |
| `severity_weighted_root_recall` | **1.0** | 5/5 |
| `all_claim_unique_root_fraction` | 0.166667 | 1/6 |
| `severity_weighted_structural_precision` | 0.192308 | 5/26 |
| `first_attempt_shard_completion` | 1.0 | 3/3 |
| claims: matched root / duplicate-or-consequence / advisory / advisory-at-planted-site | 1 / 2 / 1 / 2 | total 6 |
| `guarded_control_claim_count`, `unmatched_invariant_claim_count` | 0, 0 | |

Interpretation recorded by the scorer: `STRUCTURAL_MATCHES_NOT_SEMANTICALLY_VALIDATED_PRECISION`.
The operator reads this as: the planted root is found every time; the low structural precision is
almost entirely the same root restated per shard (2 duplicates) plus advisories, which is exactly
what the dedup design was meant to expose. No invariant claim was made against anything that is
not planted.

### 4. Guarded variant `b` — observed shards only, both attempts `INCOMPLETE_SCOPE`

Across the 3 observed shards of `b-3`/`b-4` combined: `invariant_claim_count 0`,
`guarded_control_claim_count 0`, `unmatched_invariant_claim_count 0`, advisories 2 and 5. The
model never claims the guarded invariant is broken. But **each attempt lost one shard to
`INVALID_RESPONSE` on an HTTP 200** (file-02 then file-03; different shards, so not a fixed
input). Under schema 2.0 the strict decoder rejects, most plausibly on the new nullability rule
(advisories must have class/invariant/origin all null; invariant claims all set), and the shard
record retains no reason: `generation_id null`, `response` absent, only `response_sha256`. 2 of 9
v2 shards today failed this way; 0 of 6 v1 shards did.

### 5. Requests

1. **Retain the decode-failure reason** on `INVALID_RESPONSE` (which constraint failed, which
   claim index, the offending field names; no prose) — same lever as DEVROUTE, and the run is
   otherwise blind. Also retain `error.code`/`error.message`/`Retry-After` on `HTTP_ERROR`.
2. **Within-run bounded second attempt for a shard that fails `INVALID_RESPONSE` or 429**, with
   `first_attempt_shard_completion` still scored on the first attempt only (it already is a
   separate metric). Otherwise a 3-shard run completes only when all three independent ~80 %
   events succeed, and the guarded score can never reach `COMPLETE_OBSERVATIONS` on this route.
3. The 13:12Z ledger-lockout requests (settle command; no-generation error classification)
   stand and are now the top blocker: two ledgers are already retired by 429s that cost nothing.
4. Record these as the first measured baseline under `V3-DEVBENCH-001` / `V3-SINGLE-AUDIT-001`
   context. The operator will rerun `b` until a complete guarded score exists once request 2
   or 1 lands, and will not burn further attempts blind.

## 2026-09-08T13:12Z — **DEFECT: one HTTP 429 permanently locks a development ledger. First scored run (`--truth-manifest`) refused on shard 1; ledger #1 now unusable; ledger #2 created to continue.**

Timestamp from the clock. Development ledger #1: 10 entries (9 `reconciled`, 1 `uncertain_accounted`
at 0.2032284 reserved, actual `null`). Development ledger #2 initialized (cap 250, 0 entries).
Cumulative ledger untouched. Ledger unchanged at 57 entries / `0.68118684` USD.
`completed_real_audits` remains `0`.

### 1. What happened

`development audit-corpus --truth-manifest truth-a.json` (`devbench-20260908-a-1`, route unchanged,
output `…/development-audits/unit-ledger-a-v1-scored1/`) dispatched shard `file-01` and received
**HTTP 429** from OpenRouter in 1.18 s. The observation records `diagnostics: [HTTP_ERROR,
UNKNOWN_COST]`, `generation_id: null`, `reported_cost_usd: null`, `accounting_status:
uncertain_accounted`, `accounted_cost_usd: 0.2032284` (the full reservation). The run stopped
`SHARD_INCOMPLETE` with 0/3 shards, `plan.json`, `benchmark-plan.json`, `file-01.json`, `result.json`
and `score.json` retained. No provider charge is reported anywhere.

### 2. Consequence, verified on a copy ($0)

`DevelopmentBudgetSession.reserve(...)` against a copy of ledger #1 now raises
`CostBudgetExceededError: development reservation requires all prior provider costs to be settled`.
This is the same lockout that disabled the cumulative ledger in August. A single transient provider
rate limit, with no generation created and no usage reported, has made the ledger permanently
unusable, and no supported command can settle the entry.

Code path (`development_transport.py`): line 449 `actual = _reported_cost(payload)` → `None` for an
error body (`{"error": {code, message, metadata?}}` per OpenRouter's documented error shape, no
`usage`, no `id`); line 450 raises `HTTP_ERROR`; line 492 `budget.reconcile(reservation,
actual_cost_usd=None)` → `uncertain_accounted`; line 494 appends `UNKNOWN_COST`. The conservative
"unknown = reserved maximum" rule is right when a generation *may* exist (timeouts after dispatch,
200 with missing usage). For a 4xx/5xx error body with no `id` and no `usage` there is nothing that
could later be billed against this request identity, yet the ledger treats it as an open liability
forever.

OpenRouter's error documentation does not state that 429s are unbilled; it says only that a
`Retry-After` header may accompany 429/503 and that prompt-processing cost can be charged "even if
no content is generated" (a case where a generation exists). The operator is not asserting 429 is
free; the operator is asserting the ledger has no way to ever close the question.

### 3. Requests (bounded; this is now the top blocker for any measured baseline)

1. **Settle path (already requested 05:24Z, now urgent):** an operator command that closes an
   `uncertain_accounted` entry with an explicit attestation (`operator_attested_actual_usd` or
   `closed_at_accounted_maximum`), retaining the attestation and reason. Without it every transient
   provider error retires a ledger, and the sharded path cannot run more than once per ledger on a
   bad day.
2. **Error-body classification:** when the response is a non-200 with a parseable `error` object,
   no `usage` and no generation `id`, record a typed `NO_GENERATION_ERROR` outcome with the HTTP
   status and `Retry-After` (if any), reconcile at **accounted = reserved maximum but status
   `settled_no_generation`** (or equivalent) so the entry does not block subsequent reservations
   while still counting conservatively toward the cap. Keep `uncertain_accounted` for the genuinely
   ambiguous cases. Regression: a 429 body must not block the next reservation.
3. Optional: honour `Retry-After` with one bounded wait inside the same run before declaring the
   shard incomplete, since a 3-shard run currently dies on the first 429.

### 4. Operator continuation

To keep the measured baseline moving, the operator initialized **development ledger #2**
(`~/.mmaudit/private/development-cost-ledger-2.json`, `models init-cost-ledger`, cap 250) and is
retrying the scored runs on it. Ledger #1 is retained as-is for the settle command to act on. Total
development spend across ledgers will be reported as the sum; ledger #1's uncertain 0.2032284 is an
accounting reservation, not a reported charge.

## 2026-09-08T09:22Z — **FIRST REAL SHARDED DEVELOPMENT AUDITS: both corpus variants `OBSERVED_ALL_SHARDS`. Planted defect found at the exact function; guarded variant carries no high. Three requests on scoring.**

Timestamp from the clock. Development ledger: 9 entries, total `0.2606400` USD, all `reconciled`.
Cumulative ledger untouched. Ledger unchanged at 57 entries / `0.68118684` USD.
`completed_real_audits` remains `0`. These are non-qualifying development observations.

### 1. Runs (monitoring session's shell; route `moonshotai/kimi-k3=modal/mxfp4`, frozen `…-20260908-d2`)

| run id | corpus | status | shards | cost | wall clock | output |
|---|---|---|---|---|---|---|
| `devaudit-20260908-a-1` | `unit-ledger-a-v1` (unguarded) | `OBSERVED_ALL_SHARDS` | 3/3 | 0.1147896 | 86.5 s | `~/.mmaudit/private/development-audits/unit-ledger-a-v1-run1/` |
| `devaudit-20260908-b-1` | `unit-ledger-b-v1` (guarded) | `OBSERVED_ALL_SHARDS` | 3/3 | 0.1117830 | 102.7 s | `…/unit-ledger-b-v1-run1/` |

Each output directory holds `plan.json`, `file-01..03.json`, `result.json`. Per-shard reservations
were ~0.193 USD each; actual per-shard charges 0.023–0.051 USD. No shard was unobserved, no retry,
no uncertain cost.

A first attempt at variant `a` was refused before any reservation because the output directory's
**parent** (`~/.mmaudit/private/development-audits/`) did not exist; the runner observes the parent
as an unlinked private directory before `mkdir(0o700)` of the output. Creating the parent with mode
0700 resolved it. Request 4 below.

### 2. Findings, checked against the fixtures

The only difference between the variants is `RoutePolicy.sol:40`: `a` lacks `onlyAdministrator` on
`setGateway`; `b` has it (`diff -r` confirms, other two files byte-identical).

**Variant `a` (unguarded):**
- `file-01` RoutePolicy: **high** "setGateway lacks administrator authorization" lines **40–46**
  → the planted defect, exact function span. Plus one low (pause does not restrict reconfiguration).
- `file-02` UnitRouter: **high** "gateway-only authorization undermined by permissionless setGateway
  in RoutePolicy" lines 8–32; one low; one informational.
- `file-03` UnitStore: **high** "gateway trust assumption undermined by unrestricted gateway
  selection in the inherited policy" lines 26–64; one low; two informational.

**Variant `b` (guarded):**
- `file-01` RoutePolicy: summary states the invariant is enforced. **No high.** One **medium**
  "lowering credit limits below outstanding state can silently freeze all future issuance"
  (`setCreditLimits`, lines 49–58); one low (immediate gateway rotation, no timelock); two
  informational.
- `file-02` UnitRouter: no high/medium; one low; one informational.
- `file-03` UnitStore: no high/medium; one low; two informational.

**Assessment (operator's reading, not validation):**
- Detection: the planted defect is found on its primary file at the exact lines. Good.
- Cross-file propagation: shards 2 and 3 of `a` each re-report the *same* root cause as a separate
  high anchored to their own primary file. The corpus README says findings must anchor to the
  primary file, so this is the schema working as designed, but an aggregate scorer will count
  **three highs for one defect**. This is the "variant-spam" failure mode the best-in-class
  protocol (§4, class coverage + dedup) explicitly penalizes.
- Guarded-variant precision: zero invariant false positives; one medium that is a design
  observation about `setCreditLimits` semantics (the fixture's own comment says limits restrict new
  credits only, which is what the model describes). Severity-weighted it is a soft false positive.

### 3. Requests

1. Record the first real `development audit-corpus` runs against `V3-DEVAUDIT-001` with the table
   above; `V3-DEVTRIAL-001` evidence is in the 09:15Z entry.
2. **Root-cause dedup for aggregate scoring (bounded):** give a development finding an optional
   `root_cause_ref` (file + line span of the originating defect) or an explicit
   `kind: primary | consequence`, so `result.json` can report unique root causes separately from
   per-file consequences. Without it the sharded path over-counts by the shard count.
3. The 09:15Z advisory/invariant-kind request stands; the medium on guarded `b` is the concrete
   case it would classify.
4. Output custody: either document that the output parent must pre-exist as a 0700 directory, or
   create it (0700) when the grandparent is the private root. Operator has no preference.
5. **Next capability toward the frozen objective**, for Codex to bound as a ticket: a development
   run over a *committed* synthetic corpus with a planted-truth manifest (file, line span, class)
   and an aggregate scorer producing severity-weighted recall / precision / unique-root-cause
   counts per run. That is requirement L (`SYNTHETIC_BENCHMARK` campaign) on the development
   policy, and the first thing that could make a measured baseline for the ensemble comparison.
   The operator will run whatever lands there next, unattended.

Durability: operator snapshot refreshed (`46a137d`, 308 uncommitted paths, ~120k inserted lines).
Codex's checkpoint commits remain pending the operator's direct confirmation.

## 2026-09-08T09:15Z — **`V3-DEVTRIAL-001` DONE: both fixtures `OBSERVED`. Planted violation found at the exact lines; guarded fixture not flagged as violated. Cause of the earlier mismatch now verified from retained routing evidence.**

Timestamp from the clock. Development ledger: 3 entries, total `0.0340674` USD, all `reconciled`.
Cumulative ledger untouched. Ledger unchanged at 57 entries / `0.68118684` USD.
`completed_real_audits` remains `0`. Fixture observations are non-qualifying by construction.

### 1. Results (operator's shell, route `moonshotai/kimi-k3=modal/mxfp4`, frozen `…-20260908-d2` candidate)

| request id | fixture | status | reported cost | generation id | findings |
|---|---|---|---|---|---|
| `devtrial-20260908-controlA-1` | ControlA | `INCOMPLETE` / `IDENTITY_MISMATCH` (pre-DEVROUTE) | 0.0110142 | null | discarded |
| `devtrial-20260908-controlA-2` | ControlA | **`OBSERVED`** | 0.009957 | `gen-1788858821-…` | 1 |
| `devtrial-20260908-controlB-1` | ControlB | **`OBSERVED`** | 0.0130962 | `gen-1788858872-…` | 2 |

**ControlA (violation planted):** one finding, `high`, "setLimit lacks administrator authorization",
`line_start 14 / line_end 16`. The fixture's `setLimit` body is exactly lines 14–16. Explanation and
recommendation are correct. This is the planted defect, located precisely.

**ControlB (guarded counterpart, differs only by the `require(msg.sender == administrator)` line):**
summary states the invariant is enforced. Two findings: `low` "administrator can be configured as
zero address" (lines 10–12, constructor) and `informational` "limit changes are not observable
on-chain" (lines 14–17). Neither claims the invariant is broken; both are legitimate advisory notes
on a 17-line abstract fixture. No `medium`+ finding on the guarded fixture.

**Discrimination:** severity-weighted, the pair discriminates cleanly (high on A; nothing above low
on B). Strict invariant-scored, B carries 2 false positives, because the response schema forces every
finding to populate `violated_invariant`, so advisory notes are labelled as violations of an
invariant the model itself says is enforced. See request 2.

### 2. Cause of the 06:10Z mismatch — verified, no longer a hypothesis

Retained routing evidence on both `OBSERVED` runs: `returned_model` = requested `moonshotai/kimi-k3`;
`selected_endpoints[0].model` = **`CANONICAL` `moonshotai/kimi-k3-20260715`**; provider `Modal`;
strategy `DIRECT`; `router_byok` and `usage_byok` both `FALSE`; `pipeline_count 0`;
`endpoint_total 18`. The pre-DEVROUTE validator compared the selected model against the exact id
only, which is precisely what the 06:23Z entry inferred from the August bundle. `is_byok` was
present in both locations, so the secondary risk did not materialize.

### 3. What this does and does not establish

Established: the development transport, reservation, dispatch, routing-identity binding, strict
decoding, cost capture and reconciliation work against a live provider, and the model can locate a
planted access-control defect at exact lines. Not established: audit quality on anything larger than
a 17-line fixture, any qualification, any completed audit. `V3-DEVTRIAL-001` acceptance is met on
the operator's reading; Codex to record it.

### 4. Requests

1. Record `V3-DEVTRIAL-001` with the table above as its evidence.
2. **Schema observation, bounded:** let a development finding carry `violated_invariant: null` (or a
   separate `kind: advisory | invariant_violation`) so a guarded fixture can be scored without
   counting advisories as invariant false positives. Not urgent; matters for the sharded audit scoring.
3. (Answered by `tests/fixtures/solidity/development_audit/README.md`: corpus ids
   `unit-ledger-a-v1` unguarded / `unit-ledger-b-v1` guarded, three files each.) The operator will
   run `development audit-corpus` on both variants next, under the development ledger at the same
   per-attempt target, and report per-shard results here. No confirmation needed unless the corpus
   root or output layout differs from the obvious reading.

Durability reminder stands: HEAD `4405ed3`, ~270 uncommitted paths; the operator's direct
confirmation for checkpoint commits is still pending on the operator's side, not Codex's.

## 2026-09-08T06:23Z — **FIRST REAL CALL THROUGH THE DEVELOPMENT PATH: HTTP 200, cost reconciled, observation `INCOMPLETE` / `IDENTITY_MISMATCH`. Strong evidence the router's selected-endpoint model is the canonical slug.**

Timestamp from the clock. Cumulative ledger untouched. Development ledger now 1 entry /
`0.0110142` USD, `reconciled`. Ledger unchanged at 57 entries / `0.68118684` USD.
`completed_real_audits` remains `0`.

### 1. What ran

Operator's own shell, 2026-09-08 ~06:10Z, request id `devtrial-20260908-controlA-1`, fixture
`ControlA.sol` (`d6d5c89f…`), route `moonshotai/kimi-k3=modal/mxfp4` from the fresh
`devtrial-kimi-k3-modal-20260908-d2` candidate file, development ledger, per-attempt target 0.50.

```
transport: HTTP_OBSERVATION   http_status: 200   status: INCOMPLETE
diagnostics: [IDENTITY_MISMATCH]   generation_id: null   response: null
reported_cost_usd: 0.0110142   accounted_cost_usd: 0.0110142   accounting_status: reconciled
estimated_cost_per_attempt_usd: 0.1425414
```

Positive results: the transport, reservation, dispatch, cost capture, reconciliation and the
non-qualifying markers all behaved. The actual charge was 13x below the conservative estimate.
Negative result: the response was rejected before decoding, and because the observation retains
only `response_sha256`, the operator cannot see why.

### 2. Evidence for the cause ($0, from the 2026-08-24 sealed bundle for this exact route)

`authenticated-runner-smoke-evidence-20260824-s19.json`, run 1, replay-judge usage record for
`moonshotai/kimi-k3=modal/mxfp4`:

```
requested_model:            moonshotai/kimi-k3
returned_model:             moonshotai/kimi-k3        (top-level "model")
selected_model:             moonshotai/kimi-k3-20260715   (router endpoints.available[selected].model)
canonical_model:            moonshotai/kimi-k3-20260715
response_provider_identity: Modal
router_strategy: direct   router_attempt: 1   router_pipeline: []
```

`_validate_routing` (`development_transport.py`) requires
`selected[0].get("model") == prepared.estimate.exact_model_id` and the same for `attempts[0]`. For
this route the real API returns the **canonical slug** there, so the comparison fails and raises
`IDENTITY_MISMATCH`. The production path accepts `{exact_model_id, observed_id, canonical_slug}`
(`openrouter.py:11544`, `accepted_response_models`) and bound this exact response as
`CANONICAL_MODEL_AND_ENDPOINT_BOUND` in August. The top-level `provider` = `Modal` is in the
accepted set, so the first check passes; the failure is at the selected-endpoint/attempts model.

Secondary risk, unverified: `router.get("is_byok") is not False` rejects an **absent** field. The
production path does not check `is_byok` at all, and the sealed bundle records no such field. If
OpenRouter omits it for some routes this check also raises `IDENTITY_MISMATCH`.

This is offered as strongly evidenced, not as a verified reproduction of today's bytes, because the
bytes were not retained.

### 3. Requests

1. **Fix:** in the development router validation, compare `endpoints.available[selected].model` and
   `attempts[].model` against the same accepted model set the production path uses (exact id or
   canonical slug from the bound discovery metadata), not the exact id alone. Treat absent `is_byok`
   as not-BYOK, or drop the check as production does. Regression: a router payload whose selected
   model is the canonical slug must be `OBSERVED`.
2. **Diagnosability (the lever that has resolved every prior blocker in one run):** on any
   `IDENTITY_MISMATCH`, retain the redacted routing evidence in the observation — top-level `model`
   and `provider`, and `openrouter_metadata` minus nothing secret (it contains no source, no key,
   no prompt) — plus which of the seven conditions failed, as a named sub-code. A rejected $0.01
   response that cannot be inspected costs more in operator time than any risk it carries.

### 4. Next operator step

After the fix lands: rerun `ControlA` with request id `devtrial-20260908-controlA-2` and then
`ControlB`, both against the development ledger, and report findings, false positives on the
guarded fixture, cost and runtime here.

## 2026-09-08T05:24Z — **OPERATOR DECISION AND REDIRECT: development policy is the basis for the first real single-model audit. Stop AUTONOMY/HARDHAT slices. Commit and push.**

Timestamp taken from the clock at write time (the 10:40Z label yesterday was rounded ahead; noted for
the record). Ledger unchanged at 57 entries / `0.68118684` USD. `completed_real_audits` remains `0`.

The operator (Jos Evans) reviewed the state on 2026-09-08 and delegated the unblocking decisions to
the monitoring session. These are operator decisions, not Codex inferences.

### 1. Decision — cache-write price cap

The production admission constraint is **kept unchanged**. No route may be admitted to qualification,
benchmark, or release while its charge contract is not provider-enforceable; the `input_cache_write`
refusal stands and Codex was right to refuse to filter metadata to manufacture admission.

Instead, the **development-only estimated-cost policy approved on 2026-09-06 is the authorized basis
for the empirical single-model audit baseline** (`V3-SINGLE-AUDIT-001`'s first real run). That run is
explicitly non-qualifying, non-releasable, and carries the accepted overspend risk. Its purpose is to
produce the first real audit observations so the ensemble can later be measured against a baseline,
per the 2026-09-06 priority. Certification-grade admission remains gated on a provider that offers a
request-bound cache-write or total-cost cap, exactly as Codex recorded.

### 2. Redirect — what to build next

- **Stop selecting further `V3-AUTONOMY-001` and `V3-HARDHAT-001` slices** until a real audit exists.
  The ~40 provider-free slices since 2026-09-07 are tested and honest, but on this host (no podman /
  docker, macOS) they close gates locally without real execution and do not move the
  completed real-audit count off zero. Leave both tickets PARTIAL with their current evidence.
- **Next implementation target:** extend the development transport from the two pinned fixtures to a
  bounded real sharded single-model audit path over a frozen synthetic/public corpus, under the same
  development policy, exact-byte reservation, no-fallback, ZDR, and non-qualifying markers. Select the
  smallest slice that lets the operator run one real multi-shard audit on one committed fixture set.
  Name it as a bounded ticket (e.g. `V3-DEVAUDIT-001`) with its acceptance criteria before coding.
- **Do not** relax qualification, release, or strict cost-proof types to do this.

### 3. Durability — checkpoint the work

HEAD `4405ed3` is on the remote. The working tree carries **267 uncommitted paths (~104k inserted
lines) since 2026-09-04**, snapshotted by the operator to `refs/heads/wip/durability-latest`
(`060013e`) as a safety net only. Operator instruction: **make cohesive checkpoint commits of the
tested work and publish `agent/v3-wip-checkpoint`** before selecting the next implementation.
`AGENTS.md` commit guidelines apply; nothing in them bars this. Continue to exclude private artifacts
and credentials.

### 4. Fixture trial: refused by cumulative accounting; root cause verified; separate development ledger created

The operator ran `development review-fixture` for `ControlA.sol` on the fresh
`devtrial-kimi-k3-modal-20260908-d2` candidate file (route unchanged at 05:19Z, content hash
`9e460c49…`) against the cumulative ledger. Result: the redacted refusal. The cumulative ledger was
not modified (mtime unchanged, 57 entries).

Replaying the pre-dispatch steps individually, $0, no credential values printed: snapshot parses,
`prepare_development_review` succeeds, `AtomicCostLedger.open_existing` succeeds, operator secrets
load. `DevelopmentBudgetSession.reserve(...)` on a **copy** of the cumulative ledger raises:

```
CostBudgetExceededError: development reservation requires all prior provider costs to be settled
```

The cumulative ledger holds two `uncertain_accounted` entries with `actual_cost_usd: null`:
`authrunner.smoke.r2.candidate.primary` (2026-08-23, $0.05225616 accounted, pre-fix token-detail
defect) and `authrunner.smoke.r17.judge.replay` (2026-08-24, $0.18105 accounted, operator's
2-minute timeout killed the run). Both were reported at the time; the 2026-08-22 entry asked what
resolves them and no supported reconcile surface exists (`quote reconcile` is the quote workflow;
`AtomicCostLedger.reconcile` needs the live reservation). The development policy therefore refuses
every development reservation against this ledger by design.

**Operator action:** initialized a **separate development ledger** with the supported command
`models init-cost-ledger --cost-ledger ~/.mmaudit/private/development-cost-ledger.json --config
config/openrouter-qualification.toml` (cap 250, 0 entries). The cumulative ledger is untouched and
remains the production record. Development spend will accrue in the development ledger and be
reported here per run. On a copy of the new ledger the same reservation succeeds and releases
cleanly. This is an operator accounting decision under the approved development policy, not a
change to any product invariant.

**Request (bounded, low priority):** a supported operator command that settles a historical
`uncertain_accounted` entry by recording an operator-attested actual cost or explicitly marking it
closed-at-accounted-maximum, with the attestation retained. Without it the cumulative ledger can
never accept a development reservation again.

The paid trial now runs from the operator's own shell (the monitoring session's command boundary
refuses the paid command). Results follow in a separate entry.

No other question for Codex. Acknowledge the redirect in the queue's operator-priority section.

## 2026-09-07T10:40Z — `V3-DEVREASON-001` verified: both input shapes now prepare. Trial input frozen fresh. Awaiting operator route/spend decision.

Provider-free verification of the repair, plus one metadata-only discovery. Ledger unchanged at
57 entries / `0.68118684` USD. `completed_real_audits` remains `0`.

### 1. Repair verified against the same inputs that failed at 09:25

| input | before | after |
|---|---|---|
| extracted `endpoint_snapshot` (kimi-k3=modal/mxfp4, endpoint efforts `null`, model efforts `[low,high,max]`) | `DevelopmentCostError: … requires native JSON schema and high reasoning` | `PREPARED`, `within_estimated_budget: true` |
| complete `candidate-9e460c49…json` on the same path | not accepted | parses as `OpenRouterModelDiscoveryEvidence`; `PREPARED` |

Both via `prepare_development_review(...)` with the pinned `ControlA.sol` bytes and policy
`total 250 / per-attempt 0.50 / multiplier 2 / attempts 1`. No ledger, credential, or network access
in either call. The producer answer (complete `models discover` candidate JSON on
`--endpoint-snapshot`, no extraction) is accepted and will be used.

### 2. Fresh trial input, $0

```
mmaudit models discover --candidate moonshotai/kimi-k3=modal/mxfp4 \
  --config config/openrouter-qualification.toml --secrets-env-file ~/.mmaudit/secrets.env \
  --output-dir ~/.mmaudit/private/model-discovery/devtrial-kimi-k3-modal-20260907-d1
-> Frozen 1 exact REAL discovery record; run de34b33a…; no model completion was requested.
```

Candidate file content hash `9e460c49…` is byte-identical to the 2026-08-30 h25 record, so this
route's metadata has not drifted in eight days: operational, ZDR, native JSON schema, model-level
efforts `[low,high,max]`, prices prompt `0.000003` / completion `0.000015` / cache-read `0.0000003`
per token, no cache-write component. No selection plan was needed for plain discovery.

### 3. Estimate for one attempt (from the prepared request, not a preview command)

Request bytes 2979, output allowance 4096 tokens, multiplier 2 →
`estimated_cost_per_attempt_usd: 0.1425414`. The `ControlA` + `ControlB` pair is therefore bounded
at roughly `0.29` USD estimated, with the policy's stated overspend risk accepted by the operator on
2026-09-06. Nothing has been launched.

### 4. What the operator will do next, after explicit direction

Run `development review-fixture` once per fixture against the frozen candidate file above, with the
real cumulative ledger (`--budget-usd 250` matches its cap), a distinct `--request-id` per fixture,
`--per-attempt-usd 0.50`, and report the two observations here: status, model/provider echo,
declared findings per fixture, false positives on `ControlB`, reported cost, runtime. The operator
notes for the record that `moonshotai/kimi-k3` is a judge lineage in the retired triple; for a
two-fixture transport observation that is immaterial, but it will not be reused as a candidate
without a separate decision.

No question for Codex in this entry.

## 2026-09-07T09:25Z — **`V3-DEVTRIAL-001` cannot start: `development review-fixture` refuses every real endpoint snapshot on the endpoint-level reasoning inventory. Verified at $0.**

Operator resumed monitoring today. Read the 2026-09-06/07 queue entries, the DEVCOST/DEVRUN
closures, the PLANANCESTRY answer (accepted: the operator stops probing the ancestry path), and the
README development sections. Before selecting any paid trial the operator probed the new transport
with real inputs and no credential. Ledger unchanged at 57 entries / `0.68118684` USD.
`completed_real_audits` remains `0`.

### 1. Verified defect

`prepare_development_review` (`development_review.py`) requires
`endpoint.supported_reasoning_efforts` to be non-`None` and contain `high` at the **endpoint** level.
Live OpenRouter metadata does not carry that field on any endpoint: the 2026-08-30 survey found it
absent on 112/112 endpoints, and today's live `list-endpoints --model moonshotai/kimi-k3 --json`
(schema `1.1`, 18 endpoints, 09:24Z) shows `supported_reasoning_efforts: null` on all 18 while the
new `effective` column resolves `['low','high','max']` from the model-level inventory. The
production admission path already resolves that fallback (`_reasoning_effort_result` in
`route_constraints.py`); the development path does not.

Consequence: the command refuses every real route before reading credentials, so the trial is
blocked by transport, not by model choice or spend authorization.

### 2. Reproduction, $0, no network

- Snapshot: the `endpoint_snapshot` object extracted verbatim from the frozen discovery artifact
  `~/.mmaudit/private/model-discovery/authrunner-replay-judge-20260830-h25/candidate-9e460c49…json`
  (`moonshotai/kimi-k3=modal/mxfp4`, `require_zdr: true`, `provider_policy_mode: only`, one
  endpoint, native JSON schema supported, endpoint efforts `null`, model efforts `[low,high,max]`).
  It validates as `OpenRouterEndpointSnapshotEvidence`.
- Controls: `ControlA.sol` copied byte-exact; a **copy** of the cumulative ledger; a synthetic
  `OPENROUTER_API_KEY`. All four paths absolute and distinct.

```
mmaudit development review-fixture --endpoint-snapshot <snap> --fixture-file <ControlA.sol> \
  --cost-ledger <ledger-copy> --secrets-env-file <synthetic.env> --request-id devtrial-probe-0 \
  --budget-usd 250 --per-attempt-usd 0.50 --accept-estimate-risk --allow-code-egress
-> Development fixture review refused: invalid input, consent, route, credentials, or cumulative
   accounting. (exit 2)
```

Calling `prepare_development_review(...)` directly with the same policy/snapshot/fixture gives the
typed reason: `DevelopmentCostError: development review requires native JSON schema and high
reasoning`. The refusal occurs before `AtomicCostLedger.open_existing` and before
`load_operator_secrets` (CLI order verified), so no ledger write and no egress. The ledger copy is
byte-identical to the original afterwards.

The local regression passes because `tests/fixtures/model_responses/development_cost_case.json`
sets `"reasoning": {"supported_efforts": ["high"]}` **on the endpoint** — a shape the live API has
never returned in any operator survey.

### 3. Requests

1. **Bounded ticket:** make the development review resolve the effective reasoning inventory the
   same way admission does (endpoint-level if present, else model-level), or state why the
   development path must be stricter than production admission. Please add a regression whose
   snapshot has endpoint-level `null` and model-level `[..., high, ...]`, since that is the only
   live shape.
2. **Supply route question:** is extracting `endpoint_snapshot` from a `candidate-*.json` discovery
   artifact the intended way to obtain `--endpoint-snapshot`, or should a command emit a fresh
   standalone snapshot? The README says "existing validated endpoint-snapshot JSON" without naming a
   producer. If extraction is intended, say so and the operator will use a fresh discovery run
   (metadata drifts in minutes; a week-old snapshot is not a trial input).

### 4. Second live observation

`list-endpoints --model z-ai/glm-5.2` (09:24Z) now fails closed with
`endpoint inventory contains duplicate exact routes`. On 2026-08-30 the same model enumerated 33
endpoints. Reported as an observation only; the primary judge lineage may need re-enumeration once
the provider inventory settles or once the enumeration tolerates provider-side duplicates
explicitly.

### 5. Durability note

HEAD `810ed7f` is pushed; the working tree carries 145 uncommitted paths since 2026-09-04
(≈68k inserted lines). The operator snapshotted it non-invasively to
`refs/heads/wip/durability-latest` (`2f94526`, 09:20Z). No product file was modified by the
operator.

## 2026-09-04T03:39Z — `V3-PLANADOPT-001` verified correct. New gate: candidate-less predecessor requires an authenticated ancestry transition.

Verified operator-side. Ledger unchanged at 57 entries / `0.68118684` USD.

### 1. Adoption verified

Active plan is now `14566de1f7da5e4a769502bd…`, schema `1.7`, with
`authenticated_runner_selection: null` — no active route constraints at all. The revoked
`deepseek/deepseek-v4-pro-0813=parasail/fp8` pin is gone as an active constraint; that route survives
only as a catalogue `entries` record, which is correct. `REQUEST_UNITS_V2` is absent, matching the
recorded decision not to adopt V2. Both judge lineages remain in the catalogue.

This is the right outcome and exactly what the ticket asked for: rather than pinning a tombstone, the
plan now honestly encodes that no admissible candidate exists.

### 2. New observed gate

```
mmaudit models emit-selection-plan-successor --predecessor-plan config/models.selection-plan.json \
  --candidate x-ai/grok-4.6=amazon-bedrock/us-west-2 --refresh-endpoint-inventory
-> Selection-plan successor invalid: unavailable candidate predecessor requires a
   separately authenticated ancestry transition
```

This reads as deliberate fail-closed behaviour: once the active plan records no candidate, restoring
one is not a routine successor emission. The operator is not treating it as a defect.

### 3. Question

**Does a supported "authenticated ancestry transition" exist today, and if so what performs it?**
If it is deferred to a future bounded ticket, say so and the operator will stop probing this path.
If it exists, name the command and the operator will run it.

Note the standing constraint this interacts with: the operator's survey found exactly one route of
112 live endpoints meeting every substantive candidate constraint
(`x-ai/grok-4.6=amazon-bedrock/us-west-2`), and under a verified V2 plan it still failed
`PRICE_CAP_NOT_EXPRESSIBLE,PRICE_CAP_PROOF_UNAVAILABLE`. So an ancestry transition alone may not
produce an admissible candidate; both may be required. The operator has no basis to judge the order
and is not proposing one.

`completed_real_audits` remains `0`.

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
