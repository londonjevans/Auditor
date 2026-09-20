# Source-local mutation portfolio

`V3-MUTATION-001` retains its full objective: apply, compile, execute, restore and
score all eleven required classes against real property evidence. The source-local
engineering and synthetic controls below do not complete that objective, qualify
a model or audit, or authorize execution against a real protocol.

The exact eleven requirements are listed in
`docs/evaluation/benchmark_results.json` under `B_security_mutation_testing`.
The historical five generic operations cover only three of those requirements:
authorization removal, nonce-state removal and unchecked return handling. A generic
comparator or arithmetic replacement is not evidence of changed rounding direction.
Historical evaluation observations are retained, not rewritten as current results.

## Implemented source shapes

| Required class | Supported source-local selection |
| --- | --- |
| Removed authorization | Complete explicit caller/role `require` guard |
| Removed nonce update | Consumed-state assignment or nonce increment |
| Changed rounding direction | Opposite explicit `Rounding.Floor/Ceil` or `Down/Up` modes |
| Removed stale-price validation | Complete timestamp/maximum-age comparison guard |
| External call before state update | Two separately selected statements: non-declaring assignment, then direct member call |
| Removed initializer protection | Initialization guard or `initializer` function modifier |
| Weakened timelock | Strictly reduced nonnegative duration in a timestamp lower-bound guard |
| Changed storage slot | Different exact bytes32 literal in a named slot constant |
| Removed pause enforcement | Pause guard or `whenNotPaused` function modifier |
| Unchecked return handling | Complete explicit result-success guard |
| Incorrect decimal scale | Different integer power of ten in scaling arithmetic or a scale constant |

These transformation primitives remain bounded lexical operators. Automatic compiler-bound
selection is described below. Unsupported
forms are refused rather than approximated. In particular, arbitrary rounding formulas,
versioned initializer patterns, storage-layout changes and arbitrary control-flow
reordering are not inferred. Manually constructed specifications require explicit source
spans; property applicability always requires separate evidence. A member-call shape
alone does not prove the receiver's semantic identity.

`PortfolioSourceMutationSpec` is version 2.0. It selects the exact file digest and
1–32 complete source lines, with at most 20000 characters per line and 40000 total
selected characters. Replacement source is never accepted: only the operator's
bounded token parameters or deterministic removal/reordering are allowed. Tokens
inside comments/strings, ambiguous occurrences, reversed time conditions, misplaced
modifier names and arbitrary extra statements are refused. Whole-file lexical
context is checked, including comments that begin before the selected span.

The existing disposable-copy custody remains in use. Every original file/span and
mutated file/span is hash-bound. Individual line endings, final-newline presence,
source-tree preservation, exact restoration and owned-campaign cleanup remain
checked. A compiler or executor failure cannot become a killed mutation.

## Original coverage compiler capture

The Foundry repository-suite coverage owner now passes its original per-project
`compiler_inputs` into a bounded compiler transcript capture. It uses the selected
solc bytes through an isolated `-IBS` Python helper and a byte-identical staged Forge,
with executable identities kept separate from launcher identities. Helpers stay in
the backend's existing read-only `trusted-inputs` area; the sandbox read/network
policy is not widened. The shared per-test deadline and output ceilings still apply,
including compiler input/output, runtime observations and the launch receipt.

Every accepted invocation retains received and admitted arguments, original literal
Standard JSON, compiler stdout/stderr and actual process status. Import callbacks
are disabled; a compiler error in exit-zero JSON is still a failure. The launch
receipt is hash-linked into each compiler completion, and collection refuses missing,
failed, reordered or changed populations before accepting the coverage process.
Original source and helper/tool objects are rechecked, along with the final artifact
tree. Complete CRLF-to-LF input normalization is recorded without rewriting source.

Imported Python source/cache/extension files are compared with the planned direct
file population. This is not verification of transitive native libraries or runtime
authority. The host-namespace handoff has synthetic root/LF and nested/CRLF coverage
controls under the existing macOS sandbox; remapped namespaces and full managed
dependency closure are not claimed supported by those tests. The closed input inventory
now includes both capture modules; broader runtime acceptance remains pending.

The transcript is explicitly `UNATTESTED_COMPILER_TRANSCRIPT`. It does not excuse a
missing atomic statement observation or establish a qualified coverage result. The
observed modifier-placeholder omission and creation/runtime report mismatch still
require exact compiler-to-execution reconciliation; overlapping byte/line annotations
are not a fallback. No cost, route, ledger, qualification, sealing or AUTHRUNNER policy
is changed by this diagnostic handoff.

The inventory separately records elapsed clocks, imported Python module state/flags,
dynamic attribute reads, fixed child dispatch, descriptors, stream/status observations,
readiness and process lifecycle. It binds the complete ASTs of the bootstrap and both
launcher producers, including generated literals and interpolated entrypoints, without
executing them. New, missing or changed registered input expressions refuse against the
frozen population. Historical predecessor tests retain the exact previous module,
filesystem, environment and entropy populations; every logical gate retains its original
integrity property, disposition and implementation state.

This is a conservative syntactic inventory: receiver methods such as `wait` are recorded
without asserting their object type. It is not complete dynamic dataflow analysis, a native
dependency-closure proof or managed-run admission. Other opaque behavior remains bound only
by whole-module AST fingerprints. Registration does not satisfy any previously missing gate.

### Compiler/bytecode-report phase binding

`reconcile_forge_bytecode_report` compares retained report bytes with both original
compiler bytecodes and complete compressed source maps. It checks every reported PC,
opcode and PUSH operand independently of source-ID/byte-span matching. A consistent
phase requires the entire source-map population, not a truncated prefix or nearby
source annotation. Mixed, unknown and ambiguous joins refuse. Compiler bytecode/map
hashes, every mapped instruction, jump marker, modifier depth and unmapped bytecode
tail remain available; bytes after the final mapped instruction are not treated as
executable coverage. This pure verifier does not acquire compiler or process custody.

This binding is deliberately structural, not an execution trace: reported hits and
line/column labels remain unverified observations. The original synthetic capture
controls produced both a creation-instruction/runtime-source-map mixture and a
coherent runtime report. A fresh blocked-transition control also produced a positive
reported hit on the counter-update source span while its named state invariant
passed. Correcting the displayed phase alone therefore does not supply sufficient
statement-execution evidence. No report hit or modifier-depth transition is used to
fill the missing modifier placeholder or remove an atomic obligation.

The production coverage owner still requests only its existing debug report. Native
bytecode diagnostics currently write under the disposable source workspace despite
`--report-file`; they are not an accepted private-artifact handoff. Next is exact,
phase-separated execution-PC evidence with original source/compiler custody, followed
by a justified mapping for missing modifier placeholders. Full semantic/class and
admitted real-audit acceptance remain required; no coverage authority follows from
this verifier or its synthetic controls.

Two original `forge test --debug --dump` controls now retain the debugger bytes,
machine results and both compiler calls (ABI-only selection, then the full build).
All four compiler maps and supplied source texts are cross-checked. Local addresses
are bound by exact CREATE input/output bytecode, not debugger labels or names.
Every captured PC/opcode/PUSH operand is then checked against its creation or
runtime map: 639 steps in the blocked control and 611 in the permitted control.
Modifier-body depth is observed at zero and 19 runtime steps respectively. The
dump's nine unknown-location projections retain their original compiler -1 values
as unlocated; they do not become source spans. These fixed synthetic controls now
also exercise the bounded parser below. They remain observations, not proof for
arbitrary modifier/control-flow shapes. Original process/isolation custody and
generic placeholder mapping remain required; no existing coverage or release gate
is relaxed.

### Bounded original debugger parsing

`parse_forge_debugger_observation` accepts original machine stdout, debugger dump,
every captured compiler invocation, independently supplied source bytes and an exact
selected-test descriptor. It performs no file read or execution. Version and ABI-only
compiler calls, full source populations, all trace frames and ordered execution steps
remain hash-bound. Explicit byte, JSON, call-depth, frame, step and compiler-instruction
limits refuse oversized populations rather than truncate them.

The parser cross-checks complete call-tree ordering against every debugger segment
and step, then binds PC/opcode/PUSH bytes to original creation/runtime compiler output.
Code becomes available only after successful creation, with ancestor reverts rolling
back descendant publications. Later or repeated creation, missing/ambiguous identities,
delegate/storage contexts and unlocated/generated source remain explicit liabilities.
Unresolved compiler link references currently refuse; no relocation, metadata stripping,
immutable substitution or debugger-name fallback is used. Compiler byte offsets map
through the existing exact original/CRLF-to-LF binding.

Debugger source/name annotations are hashed but are not used to select code or source
locations. `require_code_bound_steps` checks only code binding, not a test pass, atomic
statement execution or coverage. Every result is an `UNATTESTED_DEBUGGER_OBSERVATION`
with `ONE_DEBUGGER_TRACE_NOT_FULL_TEST_OR_FUZZ_POPULATION` scope, even when machine
metadata reports a larger fuzz/invariant population. Caller-supplied transcript and
descriptor hashes do not establish original process or inventory custody.

The existing coverage owner and its complete selected-test/fuzz population are unchanged.
An original-owner handoff must establish the exact execution relationship without joining
different processes as one receipt or substituting a debugger case for full coverage.
Generic modifier-placeholder mapping and full semantic/class/real-audit acceptance remain
unfinished. The closed input inventory registers this module and its eight supplied
transcript-field observations without changing existing gate definitions or readiness.

### Native coverage/debugger integration constraint

An original-launch control now compares Unit and eight-case fixed-seed Fuzz executions
inside the existing macOS no-network sandbox. On pinned Forge SHA-256
`d59ceec9d2075b1792e552289c2a4d8ac8b19195d9a6c6a76c066586a7f32757`,
`coverage --debug --dump` preserves coverage and reported fuzz counts but produces no
debugger file or machine steps. `--dump` alone is rejected before compilation.
`--decode-internal --dump` preserves those results and yields a machine trace, but
only JUMP/JUMPDEST steps are present (106 Unit / 126 Fuzz observations in this fixture),
and no debugger file is written. These results are specific to the pinned tool and
synthetic control; they do not establish a complete fuzz-trace population.

The coverage owner's command is therefore unchanged. `prepare_owned_debugger_launch`
now stages a separate fixed `forge test --debug --dump` invocation through the original
compiler capture and the existing read-only trusted-helper layout. Its own receipt binds
the exact supplied inventory descriptor and launch plan, runtime-file observations, and
writer-created stdout/stderr/dump file objects and lexical ancestors. The collector binds
every original compiler call and rechecks the bounded output population after parsing;
missing evidence, mixed coverage receipts, same-byte file replacement and aggregate
output/compiler overflow refuse. No arbitrary command or public/credentialed RPC is accepted.

Six original-inventory native controls cover permitted/blocked Unit transitions and
eight-run Fuzz selections in root/LF and nested/CRLF layouts. The original coverage
receipt/source bytes remain unchanged, while each debugger retains its own full trace.
The Fuzz controls demonstrate why shared seed and descriptor are insufficient to identify
an execution: the debugger reports a different first case from coverage. Its one retained
trace is not evidence for every reported fuzz run, even when both metadata objects say
eight runs. Neither ignored flags nor filtered decoder steps satisfy full debugger evidence.

The production suite schedules this separate debugger after a passing primary test and
original statement-coverage collection when the complete entity catalog and trusted RPC
scope recorder are supplied. It uses the same absolute per-test/suite deadline, remaining
artifact ceilings, existing isolation and mandatory terminal cleanup. Completed and failed
stage trees are charged once before interpreting the outcome; artifact overages remain
charged and stop further work. No cost or ledger policy is changed.

Manifest version1.3 retains bounded original source bytes, every compiler-call metadata
file and stream, the launch plan/receipt and separate debugger outputs. It explicitly
lists unproduced descriptors and grants neither runtime authority nor complete coverage.
The exact serialized manifest also counts against the existing suite artifact ceiling.
Legacy versions remain unchanged when no debugger evidence is retained. Local controls
reconstruct the same parsed observation from retained bytes after moving the original
workspace; this is not an independent runtime attestation or a complete managed audit.

Three full configured-runner controls additionally use the genuine built-in sandbox
preflight, original compiler-derived entity catalog and real bounded loopback RPC bridge,
without replacing admission, inventory, outcome or scope predicates. The inline-guard
control runs all four selected tests (three Unit and one eight-case Fuzz), their automatic
coverage/debugger stages and the final version1.3 manifest. The modifier counterpart still
refuses final statement evidence because each coverage report omits the compiler-owned
placeholder. The debugger does not repair that missing full-population observation.

The deliberately defective double-increment counterpart exposes a zero-completed-case
Fuzz failure. The exact-result adapter now refuses classified campaign credit before
finalization, retaining the original zero count, counterexample and output bytes. It does
not substitute the configured run count or relax the nonzero-campaign evidence schema.
Earlier failed outcomes remain recorded; the next selected test is explicitly unavailable,
and no complete statement coverage or runtime authority is granted to that failed suite.

Generic modifier-placeholder mapping, full managed-audit acceptance and semantic/class/
real-audit acceptance remain required. These host observations do not establish transitive
native-dependency closure, runtime authority or qualification. Original full-population
coverage and separate invocation/case identities remain distinct.

### Complete failure-gap retention

When the original compiler/debug producer refuses a missing atomic span, manifest
version1.4 retains the entire compiler obligation set and every selected coverage process.
The typed diagnostic binds original source/build/AST/byte/line identities, mapped and
missing report-span sets, selection/policy/inventories, separate primary/coverage machine
results, original command/stream/artifact identities and validated RPC scopes. Missing
means unknown, not uncovered; mapped does not mean executed. These records contain no
coverage status. The catalog is explicitly unvalidated and no coverage receipt is emitted.

The original suite remains FAILED and UNVERIFIED, without a successful machine summary,
coverage/qualification/safety credit or a partial-population substitute. Its original
separate debugger evidence remains one-trace-only. Complete diagnostics have a fixed
100000-reference ceiling; exceeding it refuses retention instead of truncating scope.
The complete serialized failure manifest plus previously charged artifacts must fit the
existing suite byte budget and deadline. Failed/partial writes are discarded, and a
later timeout cannot promote a known gap to real execution evidence. Versions1.0–1.3
remain unchanged on paths without these diagnostics.

Nine native modifier controls exercise allowed/blocked, nested, repeated, conditional,
early-return, empty-body and internal-helper paths. Empty bodies can execute modifier
control flow without a positive-depth instruction, and distinct conditional placeholders
share body spans. These counterexamples prohibit inferring generic placeholder coverage
from modifier depth. The full configured native modifier control retains all four original
coverage processes and their missing placeholder while still refusing statement credit.
Automatic consumption of these shortfalls, justified generic execution semantics and the
full eleven-class/admitted-audit requirements remain unfinished.

## Automatic compiler-bound discovery

`discover_portfolio_mutations` accepts immutable tuples of normalized build-info bytes,
`FoundrySourceInput` records and explicit project-relative target paths, plus the compiler
version/digest and existing finite inventory limits. It reuses
`parse_foundry_compiler_statement_catalog` to reject unrecognized source rewrites, compiler errors,
source/AST identity conflicts, malformed UTF-8 spans and incomplete input/output inventories.
It performs no filesystem access, compilation, provider call or property execution.
Consistency of supplied compiler artifacts is not independent compiler-execution custody.

For all eleven classes, the consumer derives existing mutation specifications from compiler
statements and declarations, without caller-selected line numbers or replacement source.
State writes must resolve to contract state declarations, external calls to external/public
contract functions rather than internal/library functions, and rounding modes to actual enum
members. Initializer/pause guards resolve their state declarations; result checks resolve an
adjacent external-call result declaration. Byte spans become exact bounded source lines,
with whole-file lexical context indexed once and preserved Unicode/line-ending boundaries.
Replacements are deterministic opposite rounding modes, zero delay, a changed slot literal,
or a neighboring decimal scale. No arbitrary source replacement is accepted.

`PortfolioMutationDiscovery` retains every candidate, recognized-but-unsupported attempt,
and every selected source crossed with all eleven classes. A missing supported candidate
remains an explicit limitation, not a declaration that the class is absent or inapplicable.
Inventory overflow refuses the operation instead of returning a selected prefix. Candidate
identities bind compiler build-info, source hash, declaration IDs and byte spans. Typed and
exported schemas retain all class inventories and fixed no-credit flags.

This is structural candidate discovery, not exhaustive semantic understanding. Naming remains
heuristic for nonce, initializer, pause and slot purposes; resolving a declaration does not
prove the intended security property. Opaque helpers, arbitrary storage-layout expressions,
versioned modifiers, tuple/non-adjacent result checks, arbitrary rounding formulas, scaling
through named constants and unsupported line layouts are not automatically inferred. The
manual operator's broader supported syntax must not be mistaken for automatic coverage.

`build_discovered_mutation_plan` attaches the complete discovery to a version-2.0 plan and
retains every exact candidate and coverage gap. It still requires separately established,
complete property/candidate applicability or non-applicability pairs. It cannot choose
test meanings from function names, discard awkward candidates, authorize an executor or
grant campaign credit. Legacy plans retain their original serialized shape when no
discovery is attached.

## Retained compiler-inventory handoff

`run_foundry_test_inventory` now retains a `FoundryCompilerInputSnapshot` for each
project in its `FoundryInventoryRunResult`. These private, in-memory snapshots keep
the exact normalized build-info bytes, Forge list bytes, source bytes and original
parser limits already validated by the runner. No file search, dependency fetch,
compiler re-execution or new raw-output allowance is introduced by the handoff.

`validated_foundry_compiler_input` reparses the selected snapshot and joins the
complete project population, compiler identity, original build/Forge hashes,
source bytes, parsed inventories, declaration records and statement catalog.
Changed, missing, duplicated, mutable or noncanonical input is refused. Its returned
metadata is a consistency binding, not a replacement for the scanner's live authority.

`discover_inventory_portfolio_mutations` consumes that retained result directly,
with an explicit project and project-relative target-source selection. It derives
all candidates and gaps without callers assembling AST bytes or copying compiler
identities. `build_inventory_mutation_plan` repeats the checked handoff, derives the
repository identity from the inventory, and attaches the complete compiler inventory
to the version-2 plan. The selected project must match; evidence for other inventoried
projects remains retained, without implying they are included in this mutation scope.

Every applicable test ID must match the existing executor's canonical identity for
an actual test in that selected project. Property applicability/non-applicability
still requires independently established complete bindings; matching a test name
does not establish its meaning. The new optional `compiler_inventory` field is
omitted from legacy/manual plans, retaining their original serialized bytes.

This is a library-level original-inventory-to-plan handoff, not pipeline-wide campaign
scheduling or a restart-time input loader. The evidence-backed property extension below
adds automatic direct-source challenge scheduling. Snapshot
reconstruction and JSON hashes do not recover runtime authority. The existing owned
campaign rechecks the source tree before dispatch; stale source cannot run under
an earlier plan. Source restoration, disposal and all no-credit gates remain intact.

## Source-backed generated property/test mapping

`bind_compiled_property_tests` consumes the actual `PropertyCorpus`, complete typed
`FoundryInvariantHarnessSpec` inputs and retained compiler inventory. It checks every
property evidence location against exact current source lines, then reproduces the
existing Foundry runner's complete local-deployment harness. Predicate, actors, actions,
setup, seeds, capability envelope and campaign must match the property. The compiled
declaration and execution record must bind that exact generated source, path, contract
and assertion; a familiar test name alone is insufficient. Changed source and conflicting
inputs are errors. Missing assertions or nonlocal harnesses remain unresolved.

`build_property_bound_inventory_mutation_plan` combines this mapping with automatic
compiler-bound discovery. Each mutation wholly inside a property's exact source-evidence
range is scheduled against its compiled generated assertion. New mappings also retain
`compiler_reachability`: exact source/build-bound callable regions, direct nonvirtual
internal function and modifier references, and complete per-property seed/reachable/gap
populations. Compiler declaration IDs, callable containment, source spans and call kinds
must agree; a matching helper name alone is insufficient. Modifier definitions may omit
`scope` in actual compiler output; their containing contract is checked, and a conflicting
explicit scope is refused.

Source-evidence ranges seed the compiled callable regions that contain them. A bounded
closure follows supported compiler references, including cycles, and schedules selected
mutations inside reachable regions against the exact generated assertion. The original
target-file selection does not expand: neither imported nor generated source becomes a
mutation target merely because the graph mentions it. Unsupported external/dynamic/virtual
calls, unresolved modifiers and assembly remain explicit records. State/data dependencies
and other unsupported relationships are not declared irrelevant.

This is structural challenge scheduling, not proof of path feasibility, predicate meaning,
or a guarantee that the property should kill the mutation. Default and absolute bounds are
200,000 total graph items, 100,000 property-closure work items and 1,000,000 source-seed
comparisons; invalid or excessive inputs refuse rather than producing a truncated graph.
The original compiler parser bounds still apply. All graph evidence is collected/unattested,
with feasibility, execution validation and qualification flags fixed false.

Old mappings omit `compiler_reachability` and retain their direct-only bytes and meaning.
The explicit `include_compiler_reachability=False` library mode exists for reconstruction
and comparison of that historical selection; normal new planning enables the graph by
default. Restart reconstruction reproduces the original selected mode, never silently
migrating old data. Internally consistent graph declarations can still be forged or omit
an unvisited edge: only re-derivation from the original retained compiler inputs verifies
that complete graph. The existing pipeline performs that readback before campaigns.

The optional `property_tests` plan field retains the full typed corpus, harnesses, exact
compiler records and complete bound/unresolved property population. Every candidate/property
pair is derived and checked again by plan validation. Unresolved pairs use the existing
`non_applicability` record container for compatibility, but are not exclusions in this
automatic mode: both planned and process-local scoring retain them as `INCONCLUSIVE`
denominator members. An all-unresolved automatic plan remains representable and inconclusive;
a manual plan still requires at least one binding. Legacy serialized plans omit the new field.

This does not prove independent property truth, semantic completeness, assertion execution,
or runtime authority. The native synthetic controls under `tests/fixtures/property_mutation`
exercise the original inventory writer, generated stateful assertions and owned mutation
campaigns in root and nested projects. They retain actual Forge output and verify failing
mutants, source restoration/preservation, cleanup and unresolved score members. Their MOCK
isolation grants no qualified audit credit. The source-local pipeline lifecycle below now
owns scheduling, and the retained-input reader below reconstructs its exact original plan.
Broader semantic applicability and admitted real-audit scoring remain required.

Additional synthetic controls under `tests/fixtures/property_reachability` cite only public
entry points while paused/stale-input checks live inside a modifier and nested helpers.
The old direct-only planner retains four unresolved pairs; compiler-reference scheduling
challenges the two supported guard mutations and retains the two unknown cross-property
pairs. Native root/nested controls check corresponding assertion failures, exact restoration
and cleanup, and fresh-process graph/plan reconstruction. Renamed helpers and an added Unicode
comment with LF, CRLF and mixed line endings test declaration and byte-span handling without
fixture-specific production branches. Actual Forge changes CRLF input to LF. The explicit
`CRLF_TO_LF_V1` binding now accepts only exact identity or removal of every CR immediately
preceding LF; any other rewrite is refused. Original and compiler byte hashes/sizes, exact
build/source IDs, removed-pair count and a deterministic boundary-map digest are retained.
Original source and raw compiler AST are never rewritten. Inventory, discovery and graph
spans use original bytes; coverage debug identities retain compiler byte offsets. Invalid
UTF8 boundaries and original offsets inside a transformed CRLF pair are refused. The map is
bounded to100MB per source and one million transformed pairs across the parsed build inputs;
existing lower parser limits still apply. Identical-input artifacts omit mapping metadata
and preserve their original serialization. Retained-input reconstruction independently derives
the complete map from original inputs and rejects omitted or coherently resealed false metadata.
Eight native root/nested controls cover original/renamed-Unicode LF, CRLF and mixed sources,
actual campaigns, preservation/cleanup and exact fresh-process reconstruction. Eight additional
mapped-source restart controls reject map omission or a forged digest. This establishes an
exact byte relationship, not universal semantic equivalence or execution authority.

Actual synthetic Forge coverage matches13 of14 catalog statements in all three newline
formats. Forge omits the modifier `PlaceholderStatement`; that full population remains
refused by the existing coverage producer, not accepted as complete. Forge coverage also
discards its build-info here: the comparison uses identical original pre/post inventories,
not an independently retained coverage compilation. Both limitations remain explicit.
These results do not substitute for all eleven classes or admitted full real-audit scoring.

## Source-local audit pipeline lifecycle

After generated invariant execution, the audit pipeline calls
`run_source_local_mutation_pipeline` and writes `source-local-mutations.json`.
Execution requires an EVM-capable, non-blocked run with generated invariants enabled,
the existing exact Foundry runner, an explicitly selected external compiler, and its
existing isolation/tool preparation. No dependency fetch, provider call, fork read or
tool provisioning is added. The existing fork-bound mutation executor is unchanged.

The stage retains the complete original property corpus, assigns supported properties
to their most-specific containing project, and keeps every unresolved property visible.
It copies the audited source under owned custody, adds only exact regenerated harnesses,
and binds both original and augmented inventories. The configured chain assertion is
preserved in generated source and compiler/test mapping. Each original compiler inventory
feeds the automatic complete candidate plan and existing owned mutation campaigns.

One stage-wide budget covers all projects: at most16 campaigns by default, no more than
the configured reproduction candidate/attempt bounds,30 seconds per inventory and900
seconds for stage execution admission. Replays and bounded action-removal minimization
share the same attempt/deadline object; process deadlines cannot exceed the remaining
stage deadline. Attempt slots are conservatively reserved before workspace preparation.
Existing bounded tool preparation and cleanup overhead still applies. Exhausted budgets
retain remaining candidates as inconclusive rather than silently dropping them.

Managed source-local runs consume the original prepared Forge/solc selection, including
its exact retained executable observations, configuration and disjoint material roots.
The stage reuses verified version results instead of probing again without those observations.
The inventory still uses an exact private compiler copy; a retained selection guard additionally
checks the original managed material before dispatch, after wrapping, after launch and completion,
after cleanup, and before returning parsed inventory. Same-byte inode replacements are refused.
Failed isolation wrapping also attempts bounded cleanup before reporting failure.

The shared absolute deadline reaches version probing, inventory preparation/dispatch/parsing,
and the existing native replay/minimization loop. Preparation cannot obtain a new execution
window after its deadline; timeout and tool-custody failure remain non-credit outcomes.
Cleanup is still attempted and independently bounded even after execution time expires.
These process-local checks do not establish image-side executable identity, transitive tool
closure, or a supported-kernel isolation attestation.

Private `mutations/project-NNNN` artifacts retain the original compiler inputs, original
runner results, generated source, stdout and stderr. Per-test population, source/compiler/
tool identity, process status and individual outcomes must agree across replay. A harness
aggregate does not assign the same outcome to every property. Disposable source and
execution workspaces are removed through owned directory custody, while original audited
source preservation is rechecked. Unverified preservation or disposal makes the main run
incomplete.

The artifact is explicitly `COLLECTED_UNATTESTED`. Its complete planned score remains
inconclusive without admitted runtime custody; neither serialized data nor these local
controls grant qualification, sealing, release or complete-audit authority. Synthetic
root, nested and multi-project controls exercise actual offline Forge execution and
budget exhaustion. Additional native managed controls exercise root/nested projects, the
exact selected private-output exclusion, and compiler replacement at dispatch and cleanup.
Their backend remains explicitly MOCK. Restart reconstruction is consistency-only; admitted
runtime custody and full real-audit acceptance remain unfinished.

## Retained compiler inputs and restart reconstruction

The original source-local writer now emits `compiler-inputs/manifest.json`, described by
`retained_mutation_compiler_inputs.schema.json`. The versioned manifest binds every original
evidence, Forge-list, normalized build-info, source and parser-limit file. It retains the
original runner's accounted stream bytes and generated artifact bytes; the reader does not
infer missing historical accounting. The existing project artifact binds the manifest itself.

`reconstruct_mutation_project` accepts the exact typed `MutationProjectExecution`, its
caller-selected canonical JSON SHA-256, and an absolute private project artifact root.
The hash pins the selection, not its provenance. The reader checks the complete file set,
hashes and sizes; reparses the original compiler inputs; rejoins original inventory evidence;
and regenerates the entire property/discovery plan using its original settings. Full plan
equality is required. The live pipeline performs this same readback before scheduling any
owned campaign. A fresh process can also call it without a compiler, subprocess, network
connection or input write. This does not resume an interrupted campaign or transfer runtime
execution authority.

Missing manifests in older artifacts are explicitly unsupported. No legacy values are
invented or historical artifacts repaired. Missing, extra, duplicate, reordered, noncanonical
or changed inputs are refused, including hidden files, extra directories, symlinks, hard links
and special files. Descriptor-based directory walks and bounded per-file reads check selected
root, parent and file identities; before/after observations also reject persistent same-byte
replacements during reading or parsing. These are consistency observations, not a claim that
a filesystem capability is continuously held throughout parsing or that transient
swap-and-restore activity can always be detected.

Default reconstruction bounds are 100,000 files, 256,000,000 bytes per file, 1,500,000,000
total bytes and 120 seconds. Caller bounds remain finite and cannot exceed the schema's
absolute maxima; an existing shared stage deadline further restricts time. Directory count
and depth are also bounded. Oversized inputs are refused, never truncated. Deadline checks
surround reads, parsing and final verification, but cannot forcibly preempt a blocked
synchronous operating-system call. Retained accounting and evidence do not become a runtime
capability: the returned wrapper remains `COLLECTED_UNATTESTED`, with execution validation and
qualification eligibility fixed false.

Original-writer and separate-process tests use only synthetic retained data or disposable
offline native controls. They check exact plans and original byte accounting, immutable input
bytes/identities, incomplete-input refusal and no-execution traps. This covers reconstruction,
not authenticated ancestry, campaign resumption, general semantic truth or real-audit quality.

## Plans and scoring

The legacy five-operation `SourceMutationSpec` and version-1.1
`implemented_five_class_subset` plan remain distinct and supported. A version-2.0
`required_eleven_class` plan accepts only the new specifications and accounts for
all eleven classes, including explicit missing-candidate limitations. Every selected
property/candidate pair must have an applicability binding or a non-applicability
record; an omitted pair is an error.

Version-2.0 scorecards retain both per-property and per-class/per-property scores.
Every required class must have applicable observations, and every property gate
inside every class must pass. An aggregate passing percentage cannot hide a missing
class, a weak property or an inconclusive result. Thresholds are caller-selected
through the existing interface; this capability changes no qualification policy.

Planned evidence without admitted runtime custody remains `INCONCLUSIVE`.
Process-local comparison remains comparison-only, and the benchmark engine's
runtime-crediting mutation-origin set remains empty. Serialized plans, class
scores and successful synthetic tests do not manufacture campaign, audit,
qualification, sealing or release authority.

## Local validation and remaining acceptance

The synthetic fixture is under `tests/fixtures/mutation_portfolio`; its constructor
refuses any chain ID except disposable local 31337. It has no funds, credentials,
RPC configuration, imported dependencies or FFI. The integration test uses only
already-installed external Forge/solc, in offline mode, with build outputs outside
the copied source trees. Missing tools produce an explicit skip, not a pass.

The safe suite asserts eleven named properties. Each of the eleven mutations must
compile, fail exactly its corresponding property, leave the other ten passing,
and restore exact original bytes. Those controls measure this synthetic fixture
only, not general detection quality or a full real-audit kill score. The parent
ticket still requires its original admitted execution/real-audit acceptance and
the `V3-MULTI-AUDIT-001` dependency. No provider run or tool provisioning is selected.

The additional compiler-to-discovery-to-mutation integration discovers thirteen candidates
across the eleven classes, on original, renamed and Unicode/CRLF variants. Every candidate
is compiled, run against all eleven assertions and restored exactly. The first run exposed
a surviving pause-setting owner-check removal that manual selection had omitted. The named
authorization assertion now checks that separate entry point too; the first failing native
results are retained rather than excluded. A separately compiled non-deployable lookalike
fixture proves that locals, internal/library calls and non-enum names remain gaps.

The retained-inventory integration uses the original runner with real installed Forge/solc
and an explicitly MOCK isolation backend. Root, nested and two-project layouts each
derive thirteen candidates and run every candidate through the owned campaign workflow.
The native baseline/mutant assertions, exact source preservation/restoration and owned
workspace disposal are checked; stale-source dispatch and cross-project test bindings
are refused. These synthetic comparisons deliberately remain inconclusive for production
scoring. The fixture in `tests/fixtures/mutation_inventory` retains exact native parser
inputs for provider-free unit tests and grants no live authority.

The source-local pipeline and direct-source generated-property mapping are now exercised by
the controls described above. They do not establish general semantic applicability, full
Solidity-shape coverage or admitted full real-audit scoring. Those original requirements and
the empty runtime-crediting origin set remain in force.

The archived A-V traceability remains immutable. To inspect current queue-derived
engineering status separately, use the read-only
`.venv/bin/python scripts/validate_governance_state.py --current-requirements`.
Its output includes both current and historical statuses and their coordination
hashes. A queue-derived status is not a proof of audit completion or runtime authority.
