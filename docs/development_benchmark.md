# Synthetic development measurement

`V3-DEVBENCH-001` measures the existing frozen three-file development path. It is not a
qualified benchmark, evidence of superiority, or a completed audit. Its two truth manifests are
agent-constructed, public labelled development controls, frozen independently of the scored
response. They are neither external/non-model-generated qualification truth nor an exhaustive
inventory of possible defects. They cannot satisfy frozen-objective L or blind R.

## Selection and output

The optional `--truth-manifest` on `development audit-corpus` takes the absolute path to
`tests/fixtures/solidity/development_audit/truth-a.json` for `unit-ledger-a-v1`, or `truth-b.json`
for `unit-ledger-b-v1`. Only their exact compiled byte hashes, typed content and source pins are
accepted. Changed, missing, linked, mismatched or overlapping inputs refuse before credential
loading. Existing source-egress consent, estimated-cost risk and cumulative ledger controls still
apply; this documentation does not select or authorize a paid run.

Selecting a manifest selects response version 2.0. Omitting it retains v1 request bytes and
historical observation interpretation. V1 results cannot be re-labelled v2 and scored by this
path. V2 invariant claims require a class, named invariant and bounded originating source span;
advisories require all three fields to be null. Both retain a primary-file location and severity.
Kind, location and severity remain unvalidated model hypotheses.

The output parent must already be a private, unlinked directory with mode 0700. Only the new
run directory is created. The output sequence is:

1. `plan.json` freezes exact requests and estimated costs; `benchmark-plan.json` freezes the
   selected truth and plan identity before dispatch. Truth/control IDs are not put in prompts.
2. `file-01.json` through `file-03.json` retain accepted or incomplete shard observations.
3. `result.json` retains the aggregate observation and complete available accounting.
4. `score.json` embeds that exact observation and binding, then records deterministic measurements.

Every prior output binding is revalidated before subsequent requests and finalization. A scored
artifact's typed validator recomputes all dispositions, counts, costs, times and ratios from its
inputs. JSON Schema does not replace the typed validator's relational and pin checks. Hashes and
recomputation establish consistency, not independent authentication. The explicit `MOCK_HTTP`
versus `HTTP_OBSERVATION` transport label remains part of the evidence.

Scoring failure cannot produce CLI success or erase an already retained `result.json` or ledger
charge. Output-custody failure may prevent trustworthy aggregate/score writes; missing artifacts
are not passes. Cancellation makes a best-effort incomplete result/score and propagates the
interruption. No automatic retry, fallback, ledger reset or command execution was added.

## Matching and duplicate handling

The planted control is the missing administrator guard on `RoutePolicy.sol:40`; the guarded
counterpart adds that modifier. Their router/store bytes are identical. The frozen manifest
declares the origin envelope and allowed primary/consequence source spans.

A structural match requires the frozen vulnerability class, an origin span contained in the
frozen origin and covering the required origin line, and a primary-file span contained in one
declared site. A model-authored origin alone cannot match; wrong classes, origins or primary
locations remain unmatched. Text similarity does not supply semantic validation. Ambiguous
control matches receive no arbitrary first-root credit.
A claim with matching class and coordinates can still have incorrect explanatory prose; that
semantic judgment is outside this scorer and must not be inferred from a high structural score.

The first matching invariant claim credits one planted root. Further matching primary or
cross-file claims count as `DUPLICATE_OR_CONSEQUENCE` and remain in precision denominators.
Claims against the guarded control stay separate unmatched invariant claims, not deduplicated
successes. Other unmatched claims are not automatically proven false positives: truth is not
exhaustive, and these claims may need independent investigation.

Advisories remain separate and visible. An advisory at a planted site gets no root credit and
cannot erase a miss. All claims, including advisories and informationals, remain in conservative
all-claim denominators. These measures are not ordinary validated vulnerability precision;
an optional valid advisory can lower the all-claim fraction.

## Metric definitions

Ratios are descriptive, rounded to six decimal places, with no passing threshold or overall
quality PASS. Quality ratios have `value: null` if the run is incomplete or their denominator is
zero. The numerator and full denominator remain visible, including for incomplete scope.

| Metric | Numerator / denominator |
| --- | --- |
| `unique_root_recall` | Unique structurally matched planted roots / all frozen planted roots |
| `severity_weighted_root_recall` | Frozen weight of unique matched roots / weight of all planted roots |
| `all_claim_unique_root_fraction` | Unique matched planted roots / every returned claim |
| `severity_weighted_structural_precision` | Frozen weight of unique matched roots / weight of every returned claim |
| `first_attempt_shard_completion` | Observed first-attempt shards / all three planned shards |

The last metric reports the measured completion fraction even when the run is incomplete. It
does not remove failed, unobserved or unsent shards. A complete guarded empty response has no
planted roots and no claims: recall and precision are undefined, not a manufactured 100% score.
Three matching claims for one planted root yield one unique root, two duplicates and an
all-claim fraction of 1/3, not three independent defects.

Weights are critical 10, high 5, medium 3, low 1 and informational 1. A fixed matched/guarded
control, including an advisory at a planted site, uses the truth's severity rather than the
response's severity. Every remaining claim uses its declared severity with a nonzero floor.
Severity relabelling cannot remove claims or improve unweighted root fractions; secondary
weights are descriptive, not a gate or a replacement for raw counts.

`unmatched_expected_root_ids` retains every planted root not matched. `observed_missed_root_ids`
requires observations from every declared primary/consequence file; otherwise the root stays
in `unobserved_root_ids`. Neither missing scope nor low severity suppresses it. Per-shard gaps,
missing accounting entries and missing shard runtimes are also listed explicitly.

## Cost and time

The embedded observation preserves all reservations and terminal accounting, including a failed
or discarded response. The summary separately totals reported actual costs, conservatively
accounted costs, uncertain accounted charges and active reservations. Actual costs that remain unknown stay
listed; a known-cost subtotal of zero is not evidence of a free run. No failed-attempt cost is
refunded or excluded to improve a metric.

V2 shard durations and aggregate elapsed time come from owned monotonic measurements. Missing
observations have missing shard duration, not an invented zero. The sum of observed shard times
must fit within aggregate duration. These observations do not retroactively supply the missing
fixture runtimes in the September-8 v1 operator report.
The aggregate timer starts after preflight/initial output creation and ends before final result
and score serialization; it is the owned request-loop interval, not end-to-end CLI wall time.

All `findings_validated`, `audit_complete`, `qualification_eligible` and `release_eligible` fields
remain false. Exit success means complete structural observations and successful requested
artifact production, not that roots were found, false positives rejected or source code secured.
