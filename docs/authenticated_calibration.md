# Native authenticated calibration

This is a signer-free, in-process measurement and policy-proposal API. It is not
a production qualification, a release authorization, or a complete calibration
campaign controller. The existing signed legacy format and numeric projection
remain separate and compatible.

## Input and evidence contract

`mmaudit.models.authenticated_calibration.observe_authenticated_model_calibration`
requires the exact sorted selected model IDs, the frozen benchmark suite and live
`VerifiedFrozenGroundTruth`, and one `AuthenticatedCalibrationCandidateInputs` per
selected model. Every candidate input must contain still-live original-verifier
`VerifiedCrossLineageRunnerCustody`, its configuration-bound runner evidence, and
the complete retained primary/replay custody objects and original source inputs. Missing, synthetic, revoked or
unverified execution is not accepted as a completed observation.

The measurement retains all selected candidates, including poor completed scores.
Only the original primary contributes once to the per-dimension population; all
independently judged replays remain separately visible and costed. Aliases cannot
increase the root count. Request, generation, request-body and billed-attempt
identities must not be reused. Case costs must equal all of their original ledger
attempt costs. Each source must retain the same frozen truth, public-lineage
manifest, corpus, policy and effective configuration scope.

The bound is 128 selected candidates, with 2–32 retained runs each, and 32,000,000
canonical UTF-8 JSON bytes overall. These are simultaneous bounds, not a promise
that the largest possible nested combination fits. Strict reconstruction checks
all derived distributions, counts, timestamps, hashes and retained costs. The
canonical reader rejects ambiguous, padded, coerced and oversize data. Loading or
rehashing the artifact does not create live verification.

## Policy proposal and lifetime

The observer returns an artifact and `VerifiedAuthenticatedModelCalibration`.
`derive_authenticated_calibration_policy` requires that live verification and
rebuilds the original source observation before and after derivation. Revocation
is permanent, including when cleanup reports rule drift. Capabilities cannot be
constructed directly, copied, serialized or used in another process. The runtime
also rejects drift of its frozen rule values and guarded function/model bindings.
These controls are not a general Python sandbox against arbitrary host execution.

The fixed projection requires at least eight exact candidates across six roots;
role support requires four investigator roots and two each for verifier,
falsifier and judge. The three deterministic dimensions stay at 1.0. Judgment
cutoffs use the strongest supported positive non-perfect score, with exact
denominators and jointly reachable global/role vectors. Policy validity remains
30 days and benchmark-evidence age seven days. This is empirical support, not a
statistical-significance or general audit-quality claim.

Global and role averages cover different dimension sets and cannot be compared
as ordered policy metadata. Actual role admission still independently requires
the full global Tier A result, then its own aggregate and dimension checks.
Same-dimension global floors and distribution bindings remain mandatory.

The artifact is available before policy derivation, so insufficient numeric
support does not require discarding its observations or costs. Every serialized
authority flag remains false and external sealing remains explicitly required.
The returned policy is not a trusted successor release or production selection.

## Owned in-process runner consumption

`mmaudit.orchestration.authenticated_runner_openrouter.authenticated_openrouter_runner_scope`
provides an `async with` boundary for trusted native consumers. It yields the original
`AuthenticatedRunnerExecutionResult` only after replaying its live runner proof; a consumer
can construct `AuthenticatedCalibrationCandidateInputs` from the original runner capability,
evidence and each executed run's custody while the scope is open. These references cannot
be reconstructed from JSON. The native calibration observer still applies every existing
population, truth, lineage, generation and cost check.

Consumption defaults to 30 seconds and accepts only a finite positive deadline no greater
than 300 seconds. The deadline is cooperative: it can interrupt an awaiting consumer, but
does not sandbox or forcibly preempt arbitrary synchronous Python. Late synchronous return,
late final verification, and suppressed deadline cancellation cannot produce a successful
scope exit. Observed external cancellation is propagated. The original proof is replayed
again on successful consumption, and replacement of any top-level execution-custody field
is rejected.

Every exit retains mandatory parent/child revocation, confirmation of revocation, owned
transport cleanup and secret clearing. A consumer error is not a completed calibration.
Capabilities retained after exit are revoked, including any calibration verification that
depends on them. The existing `execute_authenticated_openrouter_runner` API and CLI still
return only their detached, post-revocation, nonauthorizing data; they gain no live fields.
The scope is a library integration boundary, not an operator command or permission to run.

## Campaign-ledger accounting custody

`mmaudit.orchestration.authenticated_calibration_accounting.calibration_ledger_accounting_scope`
owns cost history for one original atomic USD 250 ledger. It is a synchronous, PID-local
accounting boundary, not a runner or provider-dispatch API. Start requires known, reconciled
history with no active reservations/holds, unknown bills, reservation overruns or exhausted
ceiling. Prior known spend remains visible and is not counted as a new campaign interval.

`retain_calibration_ledger_interval` captures an original closed interval while its exact
snapshot proof is still valid. It requires the same ledger object and identity, a contiguous
starting head, and an unchanged final snapshot. Later appends do not invalidate this
cost-only receipt if all previously captured entries and portfolio holds remain exact.
They still invalidate the original closed-runner proof. Hold cleanup must be complete before
capture; subsequent mutation of a retained hold is refused, including its released-slot
history. No ledger is copied and this module performs no ledger writes.

`observe_calibration_ledger_accounting` returns the complete current ledger, including every
new unassigned request/hold and unsafe liability. `require_calibration_accounting_ready`
refuses unassigned work as well as active reservations/holds, unknown bills, overruns and
cost at or above USD 250. `require_calibration_ledger_prefix` can project an earlier cost
fact across later known-but-unassigned work, but exposes that work and rejects current
unsafe liabilities. A missing actual bill stays unknown; only the existing ledger API can
record an actual bill. Neither this receipt nor a readiness observation admits dispatch.

There is one active owner per ledger identity, at most 128 captured intervals and 100,000
ledger entries/holds, also subject to the ledger's own file-size bound. These are simultaneous
bounds, not a guarantee that their largest nested combination fits. Exiting the scope or
losing its owner invalidates every retained receipt; copy, serialization, foreign-process
use and unissued objects cannot recreate custody. Cleanup revokes before reporting runtime
binding drift. These controls do not sandbox arbitrary Python execution.

All projections are nonauthorizing. This cost-history prerequisite does not transfer
authenticated runner, campaign or generation ownership, preserve original child capabilities
after runner scope exit, or let the calibration observer accept a detached bundle.

## Move-only generation-proof handoff

`mmaudit.models.generation_evidence.transfer_trusted_generation_verification`
consumes an original live generation proof and returns a fresh opaque handle bound to
exactly the same evidence. It requires the complete unique tuple of 1–512 original
report/case/model/provider/discovery/usage requests and replays each attestation before
and after moving the lease. Old handles become invalid; copying, serializing, reconstructing
or moving a partial request set cannot recreate them. Concurrent moves have at most one
successor. Pre-move validation failure leaves the original intact; failed successor
verification disposes the moved proof without reviving the old one.

An existing authenticated REAL-refetch origin is carried only after its original issuer,
complete request bindings, ledger identity and every original REAL usage are verified.
No origin is created when the original has none. A synthetic structural proof therefore
remains noncrediting after a successful move. This API neither contacts a provider nor
changes ledger contents, budget policy, freshness timestamps or any evidence schema.
The local tests exercise genuine structural leases; isolated origin-row migration tests
are not positive REAL-provider verification or proof of a completed campaign.

This primitive does **not** transfer a containing campaign or runner. Do not use it to
move runner-owned children inside the existing runner scope: that scope still replays its
original child handles and revokes them on exit. A coordinated campaign-child/runner
ownership handoff into the adapter/native campaign remains required; use the coordinated
transaction below only at a boundary that owns its successor. Cleanup is not silently
skipped or made tolerant of missing children.

## Move-only campaign-proof handoff

`mmaudit.benchmark.model_portfolio.transfer_trusted_candidate_benchmark_campaign_verification`
consumes one original campaign-proof handle and returns its successor. It requires the
complete ordered tuple of 1–128 original reports and exact portfolio, policy and effective
configuration hashes. The original verifier runs before and after the move. Every field of
the original immutable registry state is preserved, including journal and ledger-path
bindings; no report is rewritten, reclassified or reconstructed as live evidence.

Pre-move refusal preserves the source. Concurrent moves of the same handle have at most
one successor. A failed successor replay disposes it without reviving the old handle.
The successor remains subject to the original verifier and revoker; it cannot be copied,
serialized or inherited into a child process. This does not change the original issuer's
ability to issue a separate proof for a still-valid original journal.

The integration tests exercise the actual local journal/portfolio issuer and original
consumer using mock reports and explicitly failed unverified reports, not positive
REAL-provider qualification. The 128-report boundary preserves every case in the full
corpus but uses no-response failures to stay within the existing 5 MB portfolio limit;
it does not prove that 128 successful full-usage reports fit that limit. Moving a
campaign cannot change its report provenance, cost ledger or qualification status.
The API performs no provider access or file writes. Like the generation primitive, it
must not be applied independently to runner-owned children inside today's original scope.
The coordinated transaction below moves a containing runner. Same-ledger retention and
adapter/native campaign integration remain required; original cleanup is unchanged.

## Coordinated runner-proof move

`mmaudit.models.authenticated_runner.transfer_verified_cross_lineage_runner_custody`
requires an original live runner capability and its exact evidence. It runs the original
verifier, derives complete generation requests from the retained cases, and consumes the
parent lease before moving any child. It moves every campaign and candidate/judge generation
proof, retaining all other source, truth, lineage, report, policy and ledger references.
Only a successor passing the original verifier with the identical projection is returned,
together with its successor run-custody tuple. No durable evidence or authority flag changes.

Concurrent callers can consume a source only once. Failure before consumption preserves
the source; later failure attempts disposal of every moved or remaining child and any
registered successor, without reviving the original. Cleanup failure is reported, never
accepted as successful disposal. Original revocation remains mandatory for the successor.
The existing 2–16-run and generation proof bounds still apply. A child capability containing
more than the runner's exact request set is refused by the complete-set generation move.

This library transaction preserves the source's existing ledger lifetime; it does not itself
extend it. For an ordinary runner, the original closed-ledger proof remains unchanged:
later known spend, reservations or unknown billing invalidate it. For a runner already
retained through the explicit API below, transfer preserves that same prefix/owner binding.
Moving never discards costs. It must not be called inside today's
original OpenRouter consumption scope, which still replays and disposes its original handle.
The batch scope below owns that transition explicitly. The native calibration consumer gains
no alternate or detached proof type; the ordinary single-run scope is unchanged.

Positive transaction tests use a separate test-only runner registry and replay stand-in,
with actual local child issuers/movers/verifiers and the original local ledger verifier.
Native negative tests show those test registrations and synthetic reports still cannot
produce REAL runner or calibration authority. They do not establish positive REAL-provider
verification, a complete calibration campaign, qualification, or release.

## Authenticated retained-prefix runner custody

`mmaudit.models.authenticated_runner.retain_verified_cross_lineage_runner_custody`
accepts an original live runner, its exact evidence and the existing
`CalibrationLedgerAccounting` owner for that same ledger. The owner must have started
before the interval. The API verifies the original runner, captures its still-exact
closed interval through the accounting owner, moves all runner/child custody, and atomically
binds the successor's hidden state to the original view and its authenticated prefix.
Only the same original evidence/projection passing verification is returned. A serialized
cost projection, unissued handle, foreign ledger or already-retained runner cannot perform
this transition. Ordinary transfer may move an already-retained runner without changing
its prefix, owner, source evidence or freshness.

Native runner verification now has two explicit cost-history paths. Ordinary custody still
requires the original exact snapshot. Retained custody requires the original ledger identity,
both full snapshot hashes, every exact interval entry and cost, and its still-live accounting
owner. It then replays the original truth, lineage, portfolio, generation, response and usage
checks, and rechecks retained accounting after that replay. Later fully assigned and known-cost
intervals may coexist with the earlier proof; unassigned work pauses verification until it is
accounted for. Changed history, missing ownership, active reservations/holds, unknown bills,
overruns or the USD 250 ceiling never become acceptable. The cost-only prefix API by itself
still cannot manufacture runner or calibration authority.

The original closed-interval API is not made reusable after ledger advancement. Its implementation
and related cost types now live in `models/authenticated_runner_ledger.py`, with exact object
re-exports through the previous import path. This removes the accounting/runner initialization
cycle; published schema bytes stay unchanged. Atomic lease-state replacement invalidates any
in-flight older lease observation and cannot revive a revoked lease.

Failure does not erase captured accounting history. Once movement has occurred, failure attempts
all successor/child disposal; incomplete cleanup remains an error. Closing the accounting owner
invalidates retained verification, but does not replace mandatory runner revocation. The bounded
batch scope below owns the authenticated successor explicitly. The ordinary adapter scope still
requires and revokes its original handle, so a consumer must not invoke either move independently
inside it. Full precommitted population, external anchoring and qualification remain.

Positive local tests use original source/semantic/child/ledger replay with only the two REAL-origin
predicates and runner registry explicitly isolated. Those are not production REAL-provider proofs;
native runner retention and native calibration still reject the isolated registrations. Fresh
interpreter import-order tests prohibit network, child-process and secret access inside the child.

## Bounded OpenRouter batch ownership

`mmaudit.orchestration.authenticated_calibration_openrouter.authenticated_openrouter_calibration_scope`
accepts exact tuples of 1–128 already-loaded launches and distinct secret holders. Every launch
passes the existing provider-free preflight before the first dispatch. Candidates must be unique
and sorted; launches share the original ledger, suite, truth/lineage capabilities, effective
configuration and benchmark policy. Each launch keeps all existing route/runtime/budget gates.

The scope starts the real accounting owner before any interval, executes sequentially without
an automatic retry, and retains each runner using the original native transition. The adapter
takes cleanup ownership of the successor before any further construction, closes its transports
and clears that launch's secret holder before yielding retained custody. It does not treat a
missing original handle as proof of successful revocation. All successful runner scopes stay
owned until native consumption ends; every runner is then revoked before accounting closes,
including when a later attempt or another cleanup fails. Actual and uncertain costs remain on
the original ledger. No failed or incomplete batch yields a shortened successful population.

The yielded `AuthenticatedOpenRouterCalibrationInputs` supplies `selected_model_ids`,
`benchmark_suite`, `ground_truth` and `inputs` directly to the existing native calibration
observer. It contains no credentials or serialized authority and cannot be pickled. Original
runner verification is repeated before and after consumption; changed input references, revoked
ownership, unassigned work and all current cost liabilities remain refusals. Capabilities become
invalid on scope exit and must not escape as usable authority.

One cooperative aggregate deadline covers preflight, execution, consumption and cleanup. It
defaults to 3,600 seconds, accepts at most 86,400 seconds and also rejects synchronous late
returns or swallowed cancellation. Existing per-launch deadlines and the USD 250 ledger ceiling
are not increased. It is not a sandbox for arbitrary Python. Invalid oversized/non-tuple secret
collections are rejected before ownership; bounded accepted collections are cleared on every exit.

This is an owned selected batch, not the complete frozen calibration-population controller or
permission to dispatch. Local protocol tests use explicit stand-ins; local native-semantic
composition isolates runner registration and the two REAL-origin predicates, and the original
calibration consumer rejects those handles. Positive REAL multi-candidate qualification,
externally authenticated population sealing and release remain unproved. The registered
scope below adds local declared-population and attempt evidence, not those authorities.

## Declared-population registration and attempt evidence

`mmaudit.orchestration.authenticated_calibration_openrouter.registered_openrouter_calibration_scope`
registers **every entry** of a supplied `CandidateSelectionPlan` before the first preflight.
The active reference plan currently has twelve advisory entries; its three selected runner
routes do not replace that population. The declaration is not availability, confirmed lineage,
authenticated ancestry or an external frozen-population seal. Each supplied launch still needs
its original individually authenticated route inputs and native source proofs.

Supply the original shared ledger, exact sorted launch tuple and distinct secret holders, plus
an existing empty private evidence directory. Available launches may be a subset so missing
slots can be recorded, but any missing or refused slot prevents all runner execution. Every
available preflight is recorded before that refusal. A launch-data digest binds configuration,
corpus, policy, discovery, registries, ordered primary/replay plans and declared cost ceilings;
it deliberately does not serialize secrets, paths or opaque capabilities. Bindings are checked
before runner entry and after native consumption and cleanup.

The append-only journal records registration, each preflight, each runner entry and retained
evidence hash, and terminal consumption/failure/cancellation. Runner entry is **not** a claim
that a provider call occurred. Every event retains all declared slots and the complete original
ledger snapshot, including prior spend, actual/unknown per-request costs, reservations and
portfolio holds. An early failure retains the completed prefix, failed slot and unattempted tail.
No failed slot disappears, no smaller population yields, and no retry, ledger replacement or
unknown-cost waiver is introduced. Native USD 250 admission and qualification thresholds remain
unchanged; registration itself is allowed to record an already-unsafe ledger without using it.

Files use existing private, no-overwrite, fsynced evidence I/O. Original file/ancestor custody,
hash chain, exact transition order and bounded canonical JSON are rechecked. Bounds are 1–64
declared slots, 194 events, 4 MB per event and 32 MB total; the largest nested ledger/population
may not fit all bounds simultaneously. This narrower registration bound follows the reference
plan schema; the original selected-batch API retains its 128-candidate bound. The batch's
cooperative timeout covers its original execution/consumer/cleanup lifecycle, not synchronous
registration or final journal I/O.

`load_calibration_population_journal` requires the expected registration hash and accepts an
exact incomplete prefix as evidence. It cannot resume execution or recover live capabilities.
Process loss or storage failure may leave an `OPEN` prefix, even after some real work; a missing
terminal event is never completion. `CONSUMED` means the declared batch and consumer returned
through native cleanup, not that a calibration artifact was produced or a model qualified.
All serialized authority flags remain false. These file checks are not a sandbox against
arbitrary host execution or a substitute for an externally anchored seal.

## Registered native measurement and completion

`mmaudit.orchestration.authenticated_calibration_measurement.registered_calibration_measurement_scope`
composes the original native observer and policy derivation inside the registered batch.
It needs separate existing empty private journal and output directories, and otherwise the
same original launch/ledger inputs. All output leaves are checked before runner entry.
The scope yields the original measurement, optional policy proposal and live native proof
for trusted in-process consumption. It cannot be pickled and cannot recreate custody from data.
`execute_registered_calibration_measurement` runs that scope unattended and returns only
detached data after successful cleanup. Neither API authorizes a provider call.

The controller writes canonical `calibration.json` before attempting policy derivation.
An honest native refusal preserves that measurement and is explicitly recorded as
`NATIVE_POLICY_DERIVATION_REFUSED`, not a successful policy or a quality pass. A ValueError
is not automatically insufficient support: the original proof must still revalidate after
the refusal. Invalid source/custody/runtime aborts. The unchanged eight-candidate/six-root
and role-specific support rules apply; an available three-route subset cannot replace them.

Complete selected IDs, every registry/retained-runner hash, each closed ledger interval and
its STARTED/RETAINED journal snapshots must join. Prior known spend is counted once on the
same original ledger. Source references, current ledger and original output file/ancestor
custody are checked before and after consumption. No cost history, reservation or unknown
bill is discarded or assigned an allowance.

Every exit revokes the owned native calibration proof before runner/child/accounting cleanup;
missing custody or incomplete cleanup is an error. Only successful disposal and a consumed
population journal permit the final `measurement.json` receipt. The optional `policy.json`
is a proposal, never adoption. Publication failure can leave staged data and a CONSUMED
runner journal without a receipt: that is not completed measurement-controller execution.
There is no resume or retry path. Process loss may leave incomplete evidence.

`load_registered_calibration_measurement` requires the expected registration hash and checks
canonical files, complete journal/runner/cost joins and the fixed policy/refusal projection.
It returns data only. A self-consistent file or hash is not authentication of execution,
proof of successful disposal, external population sealing, qualification or release authority.
Measurement bytes remain bounded at 32 MB, policy at 1 MB and receipt at 64 KB; the journal's
existing bounds and the registered batch's cooperative deadline remain. Synchronous file I/O
and final publication are not forcibly preempted. Local protocol positives isolate the native
lease registry/observer and runner execution; production native observers reject those inputs.
Filesystem and ledger operations are real disposable local checks, not REAL-provider evidence.

## Population publication inputs and comparison

`mmaudit.orchestration.calibration_publication` defines two separate canonical subjects.
`build_calibration_registration_publication` reads only the original single-event journal
prefix: registration includes the complete declared population and every initial cost liability,
including missing slots. Once preflight or any other event exists, this API refuses to construct
a preregistration subject. It does not publish the registration or prove its external chronology.

`build_calibration_measurement_publication` borrows the original live native proof from
`registered_calibration_measurement_scope`. It joins the complete still-owned population,
every runner/registry/ledger interval, the same current ledger, and the original fixed policy
proposal or honest refusal. Journal bytes and original file/ancestor custody, ledger state and
borrowed source fields must remain unchanged through the last native revalidation. The builder
does not revoke or transfer the proof: the original measurement owner still disposes it before
batch cleanup. Detached or revoked evidence cannot call this native builder successfully.

`calibration_publication_request` exposes only the exact 32-byte subject digest. Full subject
bytes retain private journal/measurement material and must not be sent as the log request.
The existing transparency leaf convention hashes `0x00 || subject_digest`.
`build_calibration_publication_comparison` requires separate phase leaves, identical original
registration, matching subject digests, the same log identity, the exact registration checkpoint
as predecessor, its unchanged full leaf prefix, and a subsequent measurement leaf. Intervening
leaves are allowed. Reordered, forked, mismatched or reused evidence is not a valid comparison.

Subject and comparison readers accept only strict canonical bytes, bounded at 66 MB and 76 MB.
Embedded journal/event and native-measurement/policy limits remain 32 MB/4 MB and 32 MB/1 MB;
the journal stays bounded at 194 events. The two new schemas are data contracts, not native
capability formats. All serialized authority, external-publication, pre-dispatch-anchoring,
policy-adoption, qualification, provider-call and release flags remain false, and external
comparison remains required. These local comparisons cannot authenticate an external log or
establish that registration was publicly anchored before dispatch. No publisher, external
verification, automatic pre-dispatch anchoring, or successor release gate is implemented here.
Synthetic protocol tests use an isolated native registry, not a production REAL-positive proof.

## Native successor configuration proposal

`authenticated_calibration_config.build_authenticated_calibration_config_proposal` borrows
the original live registered measurement and its complete population-publication subject.
It requires the exact P1 qualification policy and complete effective maximum-assurance C1
configuration used by every retained native run. The original configuration, corpus, ground-truth
and policy hashes must join; the privacy profile remains `SYNTHETIC_BENCHMARK`. An honest native
policy refusal retains measurement but cannot produce a successor configuration.

The canonical proposal contains P1, the complete measured subject and exact C1/C2 configuration
strings and hashes. Its only permitted change is
`maximum_assurance.qualification.policy_sha256`, from P1 to the original derived P2. Every other
configuration field, including lineage, privacy, budget, scanner and execution controls, remains
byte-bound. Native custody is rechecked before return; original journal file/ancestor identity
must survive across both publication checks, and the caller's policy/configuration and borrowed
live fields must remain unchanged. The original measurement scope still owns proof disposal.

`proposed_successor_config_bytes` exports canonical C2 data, not an executable `AuditConfig` under
the current P1 release. Current source admission still rejects P2. Readback validates C1 under
P1; a separately source-pinned successor reader may validate C2 and reconstruct the same exact
one-field predecessor delta. Neither reader adopts a policy or recreates native custody.
No future source commit or successor release bindings are invented. Configuration strings retain
the original 2 MB bound, policies the original 1 MB bound and the measured subject all original
population/measurement limits; the outer proposal is bounded at 76 MB. These records can contain
configuration paths and complete retained measurements and are not a public-log request.

External population sealing and verified pre-dispatch anchoring, actual successor release
bindings/admission, and independent J2 qualification remain mandatory. All serialized policy,
qualification, production-selection, provider-call and release authority flags remain false.
The native artifact is not converted into the legacy signed calibration format. Local positives
rebind synthetic fixture config/policy hashes within an isolated native registry; production
native verifiers reject those stand-ins.

## Observed native successor-release inputs

`validate_authenticated_calibration_successor_release_inputs` joins the complete native
configuration proposal to a typed effective C2, this source release's captured five
qualification/corpus/truth pins, and the original opaque release-binding observation.
It compares the entire proposed C2, all release-binding fields and the exact P1/C1/P2/C2
projection. Original validators and caller inputs are rechecked after the final release
observation. Runtime pin mutation cannot turn this P1 source into a P2 release.

The result uses the existing `CalibrationReleaseTransitionArtifact` schema with the native
calibration digest. It is structural data only: no native proof is recreated, no calibration
is converted to the legacy signed format, and no `TrustedCalibratedQualificationPolicy` is
issued. A consumer must retain the full proposal and separately verify its full-population
external seal and independent replay; the transition digest alone cannot establish them.
Actual source-pinned adoption, independent J2 qualification and release admission remain
required. The validator neither creates release bindings nor chooses a future source commit.

Positive tests explicitly simulate future source pins and synthetic host measurements using
the original release-observation registry. They are not REAL release or external-origin
evidence. Existing disposable-source attestation checks cover the unchanged file-observation
boundary; this new validator performs no file or network I/O.

The operator's September-10 11:20 report supplies a limited public-documentation comparison
of Rekor and OpenTimestamps. It does not select a service or trust profile, authorize browsing,
provision a node, or publish a digest. Its compatibility conclusions are operator-reported,
not independently verified here. The frozen objective's clause 2 remains the authority and
no-signer requirement; a particular external protocol has not been adopted.

## Campaign integration still required

The unregistered selected-ID tuple is not a precommitted campaign registration. The
registered scope supplies local full-reference-plan attempt evidence and owned native
measurement/policy composition. A complete controller must still authenticate that population
externally and compose seal/release consumption. Retained-cost validation is not global budget admission. It counts prior
spend once per unambiguous closed ledger chain, sums distinct ledgers, and rejects
cost at or above USD 250; it does not discover unrelated external ledgers.

The remaining lifecycle/accounting boundaries must be handled explicitly before that
controller is usable:

- The default durable OpenRouter runner API still revokes its runner and child capabilities
  before returning. The owned scope now permits native consumption before that boundary;
  it does not preserve those capabilities after exit. Re-reading a bundle cannot recreate them.
- A live closed-runner ledger capability requires its exact final snapshot.
  Advancing the shared ledger invalidates the earlier closure. Structural chain
  measurement does not bypass that requirement. The cost-only accounting owner now
  preserves immutable prefixes and all current liabilities; authenticated evidence
  ownership is transferred by the batch scope with every non-cost source proof replayed.
  Simply substituting a cost receipt or looping the current CLI will not work. The full
  frozen-population controller must use the registered owned batch and complete the external
  seal/release consumers; an arbitrary selected batch is insufficient.

The local suite exercises real frozen-truth resolution and actual disposable
ledger behavior. Isolated lifecycle stand-ins test the lease state machine, and
the production consumer explicitly rejects their objects. None of these tests
establishes positive REAL-provider campaign authority. That integration, an
externally anchored reproducible seal, successor P2/C2 release admission and an
independent qualification campaign remain unfinished under `V3-CALIBRATE-001`.

The [offline OpenTimestamps replay reader](opentimestamps_replay.md) now supplies
bounded deterministic decoding of a documented SHA-256 proof subset using the
operator-supplied local reference. Computed commitments and claimed heights are
data only: they do not authenticate a block, publication, pre-dispatch chronology,
population seal or release. The external seal gate remains unsatisfied. Upstream
reference files are ignored/untracked and are not vendored or executed.

The same documented subset now supports bounded raw calendar-tree replay,
protocol-relative POST/GET request data and caller-nonce-bound detached submission
proof assembly. Complete reply bytes are limited to 10,000; assembly rechecks the
original full-proof limits, including its two added operations. This is an offline
wire codec, not a transport or publisher. Original request/reply custody, selected
origin, nonce entropy, authenticated chain/header evidence and full-population
pre-dispatch sealing remain required. Local supplied-proof diagnostics give two
data-only replays and five unsupported-algorithm refusals; `bad-stamp` is refused
at an unsupported operation, not proven to have an invalid anchor. No external,
provider or paid execution, protocol/trust adoption, qualification or release is
selected by this slice; `V3-CALIBRATE-001` remains unfinished.

The subsequent owned calendar transport now joins the existing publication
request through an explicit binary-digest-file convention: the detached file hash
is SHA256 of the request's 32 digest bytes, then an internally generated nonce
protects the submitted commitment. No full subject/source/journal/ledger is sent.
Complete HTTP message framing, bounded raw replies, no redirect/retry/environment
credentials, post-await subject/request binding and bounded cleanup are locally
tested. Dispatched failures and cancellation retain original nonce/request context
with possible-publication uncertainty, not success. A separate durable calendar
journal now exposes and retains the original preparation pin before dispatch,
fsyncs a POST intent and restricts reopened recovery to GET at the original
commitment. Missing/failed/cancelled outcomes remain visible, with fixed event and
lookup limits, private-file custody and nonblocking process exclusion. Partial
or altered tails refuse without silent repair or POST replay. Callers must retain
the original subject/origin/preparation pin and finish the fresh owner's scope;
this local journal is not rollback-proof external chronology or a complete
population publisher. Local loopback HTTP tests
do not authenticate a real HTTPS origin; transport records are constructible data,
not external seal authority. No live publication, chain/trust adoption, paid call
or native release is selected, and every existing security gate remains mandatory.

The source-owned `calibration_calendar_publication` adapter now retains the full
private subject and an exact publication descriptor before dispatch. Registration
uses the original single-event journal; measurement borrows the original live
native proof/ledger and joins its original registration descriptor/population.
Original source/proof/field identities and file custody are rechecked across the
HTTP await and enclosing cleanup. A later source refusal is not overridden by a
replayed child calendar response. Readback and GET recovery reconstruct data only,
even if the original source or native lease is no longer available. The descriptor
does not establish external publication or pre-dispatch chronology. The explicit
`calibration_calendar_controller` path now connects recording to the original
registration-before-preflight and live-measurement-before-disposal boundaries;
the ordinary no-calendar APIs keep their existing defaults. See the
source-owned handoff section in `docs/opentimestamps_replay.md`; no existing
qualification, lineage, seal, native-adoption or release gate is relaxed.

The controller records each phase using the original source-owned preparer and
retains its original descriptor/subject/child-event file custody through intervening
batch work. Missing slots and every available preflight refusal remain visible.
Failed/cancelled exchanges stop the recording path without retry; pending/opaque
proofs remain unverified data and cannot authorize model dispatch or qualification.
Contact is explicit and the overall deadline includes registration, measurement,
cleanup and final readback. Original native outputs are retained before proof
disposal, and the final receipt, original terminal population and exact ledger
are checked again before returning detached data. A late source/ledger change
cannot be hidden behind an earlier successful native receipt. The result still
does not establish externally anchored chronology, P2/C2 adoption or independent
J2; no real provider or public calendar was exercised by these local tests.
