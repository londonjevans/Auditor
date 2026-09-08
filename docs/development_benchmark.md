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

The v2 finding model owns the kind/nullability contract used by raw model schemas, the
actual provider request and generated public schemas. It exports two complete, closed `anyOf`
object alternatives with disjoint `kind` values. In the `advisory` branch, `vulnerability_class`,
`violated_invariant` and `root_cause_ref` must all be JSON null; in the `invariant_violation`
branch all three must be non-null. Every existing field remains required. The v2 prompt names
these exact fields. Strict client validation and source bounds remain authoritative: no metadata
is dropped, kind changed or rejected content repaired to make a response pass.

This alignment changes v2 request bytes and their byte-based estimates and plan bindings.
Prepare fresh estimates/plans for any separately authorized future attempt; the existing runner
rejects changed prepared requests before reservation or output. V1 bytes and historical response
interpretation remain unchanged. Local JSON Schema and mock-HTTP checks establish kind/nullability
parity, not every semantic invariant or real-provider acceptance of the revised schema. No paid
verification, retry or billing-policy change is implied.

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

## Explaining rejected development responses

New incomplete fixture/shard observations may include `rejection_evidence`. It separates HTTP-body,
completion-envelope, structured-output and source-scope failures while retaining the existing
`INVALID_RESPONSE` diagnostic. The nested `response_sha256` must match its parent observation.
If encoding, length or size checks refuse before a whole body is read, both hashes remain null;
this does not assert custody of unseen response bytes. Old observations without this field still
parse, and successful observations do not gain a new null field.

Structured rejection retains the original strict decoder's failure code, including syntax,
duplicate-key, nonfinite-number or schema rejection. For a schema rejection only, a diagnostic
revalidation against the same captured schema generation can project at most eight issues. Each
contains a constant constraint name, an allowlisted field name and, when applicable, a zero-based
finding index from 0 through 15. `schema_issues_truncated` reports a discarded suffix. Unknown
keys map to their known container, never to the input-authored key. Values, model prose, error
messages and validation contexts are never retained. Cross-field validation may report only its
first failing constraint; the issue list is not an exhaustive explanation of every defect.

For example, a synthetic advisory with a non-null `vulnerability_class` remains rejected with
`ADVISORY_FIELD_MUST_BE_NULL`, that constant field name and its finding index. Missing evidence or
schema-generation drift leaves the finer detail absent. A successful diagnostic revalidation can
never override the original rejection. This path does not repair content, relax a schema, retry,
select a provider, settle uncertain costs or promote a partial score to complete scope. The
September-8 14:28 report names an advisory `root_cause_ref` nullability rejection; its private
response bytes remain unauthenticated here. The later 15:02 report records three conforming guarded
shards and a complete synthetic baseline pair; this is operator-reported development evidence,
not independently authenticated provider acceptance or a qualified audit. These local synthetic
controls do not reconstruct private response bytes. HTTP error messages/Retry-After handling and
accounting recovery are separate work; no charge is inferred from an absent generation identifier.

## Completion-envelope telemetry without another request

New fixture and audit-shard observations retain optional `completion_telemetry` after the whole
bounded response body has passed strict JSON decoding. It is also embedded in the aggregate,
score and any subsequent comparison. This covers successful responses as well as incomplete
output, identity/structured/secret-output refusals and parsed HTTP-error bodies. A timeout,
unread/oversized body, duplicate-key/nonfinite JSON or non-object response cannot supply it.

Each prompt, completion, total and reasoning count has a `state` and nullable `value`. Only exact
integers from 0 through 4,000,000 are `REPORTED`; absent/null fields are `NOT_REPORTED`, while
invalid fields or containers are `INVALID`. Booleans, numeric strings, decimals and out-of-range
values are never coerced. Reasoning counts come only from `usage.completion_tokens_details`.
Individually reported inconsistent counts remain exact; `token_sum_consistency` and
`reasoning_subset_consistency` are recomputed as `CONSISTENT`, `INCONSISTENT` or `NOT_OBSERVED`.
They describe relationships, not correct usage, billing settlement or accepted request limits.

The normalized `finish_reason` retains only `stop`, `length`, `tool_calls`, `content_filter` or
`error`. Native reasons retain a finite allowlist of known completion/limit/tool/error spellings,
case-folded as in the existing admission check. Unknown strings become `UNRECOGNIZED` with no
retained value. Missing/null and invalid values stay distinct. Zero/multiple choices produce
`AMBIGUOUS`, and a malformed or nonzero-index singleton produces `INVALID`; the projection never
silently picks a choice. Arbitrary native reasons, provider errors, model prose and credentials
are not retained. The field paths and normalized finish vocabulary follow the
[OpenRouter response reference](https://openrouter.ai/docs/api_reference/overview); metadata may
still be missing or invalid on an actual failure.

Telemetry must match the parent's exact response hash and observed HTTP status. Its fixed
`REPORTED_METADATA_NOT_VERIFIED_USAGE` interpretation grants no identity, accounting, finding or
audit authority. Hash consistency is not private-provider authentication. Existing admission,
source scope, strict decoder, reported-cost reconciliation, unknown/overrun liabilities and
one-attempt behavior are unchanged. A diagnostic projection failure leaves metadata absent; it
cannot repair a refusal or override admission. Old observations omit this optional field and
remain parseable. No telemetry is backfilled, no counts are inferred from prices, and no request,
retry, effort/budget change or generation lookup is selected by retaining these fields.

## Comparing retained runs without another provider call

`mmaudit development compare-scores` accepts two through eight explicit absolute
`--score-file` paths and one absolute `--output-file`. Each input must be a retained v2
`score.json` for the same exact frozen corpus, truth, scorer version and transport class.
Compare planted and guarded variants separately; do not pool unlike controls into one ratio.
The output parent must already exist, be owned and not group/world-writable; the output file
must not exist. Files and parent paths cannot traverse links, and input/output paths must be
distinct. The writer creates one mode-0600 file, never directories or a ledger.

Every score and its derived metrics are strictly revalidated. Rows are ordered by run ID and
retain model/endpoint labels, completion-token allowance and the complete existing summary,
including incomplete shards, misses, duplicates, guarded claims, missing costs and timings.
Run/request/reservation and known generation identities must not be reused across inputs.
An equal error-body hash alone is not proof of a duplicated request: separate failed calls can
return identical bodies, and their costs must remain visible. A failed repeated generation
inside one already-validated run stays failure evidence, not a reason to erase that run's cost.

Each row lists roots unique to that run and roots shared with another input. The union counts
each observed frozen root once; its conservative all-claim fraction divides that count by
**all** claims across **all** selected runs, keeping repeated consequences and advisories.
The union's quality ratios are null if any input has incomplete observations, even if another
run found the planted root. Shard completion always uses the full three-times-run-count
denominator. Empty truth never produces perfect recall. Every original score is embedded and
hash-bound, and all rows/union metrics are recomputed when the comparison is parsed.

Estimated, reported-actual, accounted, uncertain and active-reserved costs are summed separately.
The sum of owned run durations is not a measured ensemble wall clock: the union was not executed,
and `executed_ensemble_wall_clock_seconds` stays null. Model names do not prove independent
root lineages; effort/request and budget parity are not established by these artifacts. The
comparison cannot claim a controlled experiment, semantic precision, superiority, qualification
or audit completion. The truth remains agent-constructed/public-labelled development material.
Including failed runs is essential; comparing hand-picked successful runs cannot establish an
unbiased campaign completion rate. This command does not discover or select omitted runs.

The command reads no credentials or ledgers, calls no provider and performs no retries. Exact
input byte bindings are checked before writing and again while the created output is still owned;
input/output drift refuses success. Existing or replacement output files are not overwritten or
deleted. Complete observations return success; a safely retained comparison containing incomplete
observations returns `INCOMPLETE`. Bad input or file custody returns a redacted configuration error.
These filesystem checks establish observed consistency, not authentication of private provider
execution or protection against an actor that controls the whole host after validation.

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
