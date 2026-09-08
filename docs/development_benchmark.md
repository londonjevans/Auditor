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

## Continuing development with an uncertain estimated charge

Development cost policy still defaults to `uncertain_cost_policy: STOP`. An unknown charge
remains `UNCERTAIN_ACCOUNTED`, with `actual_cost_usd: null` and its full reserved estimate
counted against the same cumulative budget. An error status or missing id/usage does not prove
zero cost or that no generation occurred. The default therefore blocks later development requests.

`preview-cost`, `review-fixture` and `audit-corpus` accept the optional
`--carry-uncertain-estimates` flag. It selects `CARRY_RESERVED_ESTIMATE` in the existing typed
development policy; the selected mode is retained in estimates, frozen plans and observations.
The existing `--accept-estimate-risk` acknowledgement is still required, as is
`--allow-code-egress` for paid-capable commands. This is pre-run configuration, not per-error
settlement or permission to choose a model, source, ledger, endpoint or a paid attempt.

In this mode, a later separately selected attempt or new run can use the remaining estimated
budget on the **same ledger**, without discarding history or resetting the cap. Only fully
accounted unknown entries in the existing canonical development request namespace are eligible.
That namespace is an accounting convention, not authenticated proof of provider origin. Up to
4,096 exact request/reservation/amount handles are revalidated under the same ledger lock as
the new reservation. Stale, changed, duplicated or newly unlisted uncertainty still refuses.
Pending requests, held portfolio slots, foreign unknown entries, prior overruns, insufficient
remaining budget and reused request/run identities also refuse. Reopening the ledger neither
settles unknown entries nor changes these checks.

The prior unknown records and failed artifacts remain unchanged. Each failed current run still
ends incomplete: this feature does not retry, resume missing shards, classify a request as free,
release a reservation, or fabricate known charges. Existing known-cost reconciliation can still
replace an unknown amount with observed cost; a resulting overrun remains blocking. Run and
score totals stay run-scoped, while the ledger includes all historical estimated liabilities;
do not substitute the latest successful run's subtotal for cumulative accounting.

Estimates can be exceeded, including by carried unknown charges. This opt-in is not a
provider-enforced ceiling, strict-cost proof, qualification or completed audit. Default policy
serialization and provider request bytes remain unchanged; old observations are not backfilled.
Local synthetic CLI/mock-HTTP tests exercise both corpora and schema versions across 429,
missing-cost, malformed-JSON and timeout failures followed by a separately selected run. These
controls do not authenticate private billing or demonstrate an actual provider recovery.

## Executed development candidate review

`development judge-audit` executes a second-model review of one retained, complete v2
`audit-corpus` result. This supplies a candidate-to-judge stage, not a complete specialist
ensemble, qualified cross-lineage adjudication or an autonomous real audit. It is paid-capable;
this documentation and the local regression results do not select a provider run.

Supply `--candidate-audit-file`, `--endpoint-snapshot`, `--corpus-root`, the original
`--cost-ledger`, `--secrets-env-file`, a fresh `--output-dir` and `--run-id`, plus the existing
`--budget-usd`, `--per-attempt-usd`, `--accept-estimate-risk` and `--allow-code-egress` controls.
Paths must be absolute, distinct and normalized. Optional `--truth-manifest` selects the same
exact local truth used for the candidate audit and writes a review-impact score. The corpus ID
comes from the candidate plan; an incomplete or v1 audit is refused, not silently reinterpreted.
`--maximum-completion-tokens`, `--maximum-run-seconds`, `--safety-multiplier` and the explicit
`--carry-uncertain-estimates` policy retain their existing limits and risk meaning.

The runner binds the original candidate audit, every unchanged finding, reviewer metadata,
full frozen source and exact byte-estimated requests in `plan.json` before dispatch. It sends
one request for each nonempty primary-file candidate shard, up to three requests and 48
candidates. Source, comments and candidate prose are untrusted data. Truth, score, candidate
summary and producer identity metadata are not inserted into the judge prompt; model-written
finding prose is retained unchanged, so this is not a guarantee of semantic blinding or the
removal of identity hints that a candidate itself contains. No model-generated code or command
is executed. Identical requested IDs and metadata-known canonical aliases are refused.
Distinct IDs are only an exclusion check: `lineage_independence` stays `NOT_ESTABLISHED`.

Each supplied claim ID must receive exactly one ordered `SUPPORTED`, `REFUTED` or
`INCONCLUSIVE` opinion. The judge cannot introduce, edit or merge findings. Supported and
refuted decisions require at least one bounded source reference; wire and public JSON schemas
export that requirement, while typed validation also enforces exact candidate coverage,
unique references and actual corpus line bounds. A citation is not proof of semantic validity.
Missing, duplicate, reordered, invented or out-of-scope decisions refuse the whole response;
they are neither repaired nor counted as a completed review. Inconclusive decisions count as
observed responses, never as support or refutation.

The existing ledger must contain the exact original candidate request/reservation identities,
states and costs, and its cumulative target cannot be reset. This checks retained accounting
consistency; it does not independently authenticate billing, ledger-file provenance or prevent
an operator from making filesystem copies. Existing holds, overruns, budget exhaustion and
unlisted uncertainty still block. Each failed current review stops with no automatic retry.
The separately selected carry policy may permit a later run while retaining old unknown
estimates in full. The candidate's original files and all its costs stay unchanged.

The new private output directory uses the existing mode 0700/0600 and owned-file protections:
`plan.json`, optional `benchmark-plan.json`, one `file-0N.json` per observed or failed request,
then `result.json` and optional `score.json`. Each prior output binding is rechecked before
another request and finalization. Interrupted requests retain ledger accounting, including an
unobserved uncertain or still-reserved entry where appropriate. Cancellation is re-raised after
best-effort finalization. Failed output custody can prevent a result file, never erase a charge
or turn a missing result into success. Existing output directories and paid request IDs cannot
be replayed under a new output path.

If every candidate list is empty, the result is `NO_CANDIDATES`: no judgment request, zero
judgment completions and no new ledger entry. A successful CLI return for that local operation
is not evidence of a completed judgment or safety. Its observation-rate denominator is empty
and its value is null. On a planted corpus, no candidates means zero root recall; an empty
expected-root denominator does not mean perfect recall.

The `development_judgment_impact_score` embeds both the original candidate score and the exact
review observation. It does not fabricate a filtered audit or change original dispositions.
Every original claim retains its structural classification and an opinion or `UNREVIEWED`.
Supported planted roots are deduplicated even if the originally designated first match was
refuted but another same-root candidate was supported. Supported guarded, unmatched and
advisory claims remain visible; refuted planted candidates, inconclusive and missing reviews
are counted separately. All complete-quality ratios become `INCOMPLETE_SCOPE` with null values
when the review stage fails, while the actual first-attempt observation fraction stays visible.

`supported_severity_weighted_structural_precision` uses only supported claims in its
denominator. `all_candidate_severity_weighted_structural_precision` preserves every original
candidate, including refuted, inconclusive and unreviewed ones. Both count each supported
planted root only once and are structural measurements, not validated precision. Reporting both
prevents a filtered support set from concealing the initial candidate noise. The original
candidate score remains available unchanged.

`judgment_accounted_cost_usd` covers this review stage; `combined_accounted_cost_usd` adds this
one candidate audit exactly once. Neither is the entire historical ledger total, which can also
include other attempts and uncertain liabilities. Multiple reviews sharing a candidate must
not sum their combined totals and charge the same candidate repeatedly. `elapsed_seconds` is
the owned review-stage duration; `summed_stage_elapsed_seconds` adds the retained candidate
duration and is not end-to-end ensemble latency or a controlled parallel experiment.

All artifacts remain non-qualifying: model opinions, requested-ID diversity, synthetic scores
and recomputable hashes cannot establish independent roots, external ground-truth provenance,
an evidence-anchored seal, guaranteed budget enforcement, validated findings or superiority.
The existing strict qualified runner and frozen objective are unchanged.

## Executed development candidate and dual-review ensemble

`development ensemble-corpus` joins one v2 candidate audit and two source-grounded reviews
in a single owned run. It is paid-capable; documentation and synthetic tests do not select a
provider run. This is development automation, not the qualified three-configuration ensemble
experiment, an independently validated audit or evidence of superiority.

Supply three explicit metadata files using `--candidate-endpoint-snapshot`,
`--first-reviewer-endpoint-snapshot` and `--second-reviewer-endpoint-snapshot`, plus
`--corpus-root`, `--corpus-id`, one existing `--cost-ledger`, `--secrets-env-file`, a fresh
`--output-dir` and `--run-id`. The existing `--budget-usd`, `--per-attempt-usd`,
`--safety-multiplier`, `--accept-estimate-risk`, `--allow-code-egress` and optional
`--carry-uncertain-estimates` retain their meanings. Paths must be absolute, distinct,
normalized and outside output scope. Only the two frozen three-file local corpora are admitted.
`--truth-manifest` is optional and consumed only by local scoring, never model prompts.

All three roles have separately selected token allowances: `--candidate-maximum-completion-tokens`,
`--first-reviewer-maximum-completion-tokens` and `--second-reviewer-maximum-completion-tokens`.
Each defaults to 4096 and must fit its own endpoint metadata and exact request estimate.
The candidate's allowance does not force either review's allowance. The whole-run
`--maximum-run-seconds` defaults to 600 and is bounded to 1800. Requested model identities and
known canonical aliases must be pairwise distinct; names do not establish independent roots,
and `lineage_independence` remains `NOT_ESTABLISHED`.

The frozen parent plan preflights the candidate estimate plus six per-attempt review allowances
against the same ledger's remaining estimated budget. This is headroom, not a portfolio reservation
or a provider-enforced ceiling. Each actual review request is constructed only after candidates
exist and must independently fit its allowance. Concurrent spending, uncertainty or an actual
overrun can therefore stop a later stage despite successful initial preflight. Prior liabilities
remain in the original ledger; a run cannot reset them or silently retry.

Execution is sequential: three candidate requests, then up to three requests for each review,
at most nine first attempts and 48 unchanged candidates. Both reviews receive the same original
candidates and frozen source. Neither sees the other review, score or truth. Untrusted candidate
prose is unchanged, so this does not guarantee semantic blinding. Every nonempty shard requires
exact ordered decisions; malformed, missing or duplicate decisions stop the stage. Generation
IDs cannot be reused across roles. There is no automatic retry, repair or model-generated execution.

The private parent directory contains `plan.json`, optional `benchmark-plan.json`, exact
`review-01-plan.json` and `review-02-plan.json` when prepared, `result.json` and optional
`score.json`. Child directories `candidate/`, `review-01/` and `review-02/` retain their original
plan, shard observations and result. Parent and completed child bindings are rechecked between
stages and at finalization; each child keeps its own per-request custody checks. Parent/prior-child
tampering during a child can prevent the next stage or final result, not retroactively cancel
that child's already dispatched requests. Charges survive custody failure. The existing child
artifact limit remains 2 MB; composed parent results/scores have an explicit 16 MB limit.

`OBSERVED_ALL_STAGES` means all three stages returned complete observations, not validated
findings. Empty candidate sets produce `NO_CANDIDATES` after the three source requests and
dispatch neither review: one observed stage out of three, zero judgments and a null opinion
rate, never perfect recall. `INCOMPLETE` retains every observed original claim, missing stage,
unknown/reserved liability and failed response. A cancelled or otherwise unreturned child earns
no fabricated observation credit even if some child files exist; known request accounting remains.
Cancellation is re-raised after best-effort finalization. Custody failure can prevent a parent
result altogether, without implying success or zero charge.

`TWO_REVIEW_UNANIMOUS_OPINION_ONLY` preserves both opinions per original claim: two supports
or two refutations agree; differing opinions or an inconclusive review yield `INCONCLUSIVE`;
any missing review yields `UNREVIEWED`. Agreement does not validate a vulnerability. The score
keeps the original candidate score and every structural denominator, including guarded,
unmatched and advisory noise. It reuses the review-impact metrics above without synthesizing a
filtered candidate audit. Incomplete runs keep complete-quality ratios null.

`review_opinion_observation_rate` counts actual individual opinions over twice the number of
retained candidate claims, with an empty denominator reported as null; it does not invent claims
from missing source shards. `stage_observation_rate` always uses three stages. Parent accounted
cost sums unique candidate and review entries once, not each review's candidate-inclusive total.
This run total can be smaller than the entire ledger total, which retains other attempts.
`executed_ensemble_wall_clock_seconds` measures the owned execution interval after preparation
and initial output setup, before final parent result/score serialization. It includes stage handoff
and any unreturned child work. The separate observed-stage sum contains only returned child
durations; missing durations are not invented. Neither measurement is a controlled parallel run.

Synthetic local integration tests trap real network and process execution and use disposable
ledgers with explicit fake credentials. They cover both corpora, maximum and empty scope,
agreement/disagreement, failures in each stage, carry, overruns, deadlines, cancellation,
generation reuse, output custody, CLI consent and score tampering. They do not demonstrate
live negative-control discrimination, private billing authenticity, external truth provenance,
genuine root independence, a reproducible external evidence seal or the frozen hard-cost objective.
All qualification, release, audit-completion and finding-validation authority stays false.

## Explicit source-manifest development candidates

`development audit-manifest` reviews a supplied local source inventory beyond the two
fixed three-file controls. It accepts an absolute `--source-manifest` and `--corpus-root`,
explicit endpoint metadata, the existing cumulative cost ledger, a distinct new output
directory and run ID. Both `--accept-estimate-risk` and `--allow-code-egress` are required
before any input is read. This is a paid-capable development command, not a selected
operator run or a qualifying audit.

Prepare the typed manifest with the pure `freeze_development_corpus` API using an
explicit, sorted tuple of `(relative_filename, original_bytes)`. It performs no file
discovery or I/O. The CLI consumes that manifest; it does not find sources, follow imports,
download dependencies, compile or execute Solidity. Scope must be declared
`OPERATOR_SUPPLIED_SYNTHETIC` or `OPERATOR_SUPPLIED_PUBLIC`, but that declaration and its
hash do not authenticate provenance, licensing or ground truth. `EXPLICIT_MANIFEST_ONLY`
and `dependency_closure: NOT_ESTABLISHED` remain fixed.

The inventory permits 1–64 lexicographically sorted, case-fold-distinct relative `.sol`
paths, at most 65536 bytes and 10000 lines per source, and 524288 total original bytes.
The loader refuses traversal, aliases, links, hard-linked/special files, malformed or
ambiguous UTF-8, secret-like content and any exact path/byte/hash/line drift. It reads only
selected members and revalidates their bindings before handing off the immutable snapshot.
These global bounds do not promise that the selected endpoint's request/token capacity
or the estimated budget can admit every otherwise valid corpus.

Each selected file receives one request with its entire primary file and the entire
selected source snapshot as context. Requests share one exact model/metadata selection,
completion allowance and one-attempt estimated-cost policy. Full context is repeated per
file, so input cost scales with both corpus size and file count; this is not semantic
dependency-aware sharding. The existing independent 180-second request cap still applies,
within a whole-run `--maximum-run-seconds` deadline (default600, maximum1800). There is no
automatic retry or resume, and estimated costs are not a provider-enforced ceiling.
Explicit carry mode preserves prior eligible uncertain estimates as liabilities.

The v3 response permits up to16 unvalidated claims per file with exact nested origin paths
and source-bounded primary/origin lines. It retains the coarse v2 vulnerability classes
(including `other`) and advisory/invariant distinction; v1/v2 schemas and fixed source
allowlists remain unchanged. Coordinate validity is not semantic correctness.

Owned mode0700 output retains `plan.json`, exact original UTF-8 material in `sources.json`,
observed `file-0001.json` through at most `file-0064.json`, and `result.json`, all mode0600.
Every selected file/line and candidate remains in the denominator; failures, missing shards,
unreturned requests and unknown/overrun costs remain visible. Generation reuse, replay and
owned-output drift refuse. Completion means responses were observed for selected files:
`RESPONSE_COMPLETION_NOT_VALIDATED_ANALYSIS_COVERAGE`. All audit, validation, qualification
and release flags remain false, including when every response contains no findings.

This candidate consumer does not yet supply general-manifest truth scoring, candidate
judgment or the dual-review ensemble. Those existing commands retain their fixed v2
three-file scope. Local tests use the larger paired synthetic source fixture and a64-file
boundary with exact MockTransport and real network/process traps; they do not demonstrate
real-model quality, whole-protocol coverage, independent roots or a completed autonomous audit.

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
