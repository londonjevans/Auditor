# Proposed v3 tickets — dependency closure and audit-run defects (revised)

Source: the 2026-09-13 ForestRoadVault dual-chain development-path run (125 files, ledger-5,
`~/.mmaudit/private/development-audits/frv-full-20260913/`). Operator-reported, nonauthorizing.
No ticket requests a provider call; all are provider-free engineering.

**Revision note.** A first draft of this document was audited on 2026-09-14 against the product
goal — a fully automated auditor whose findings are sound — and against the tree. The audit found
one material error and four omissions; they are corrected below and listed at the end so the
reasoning is inspectable.

Priority order is as listed. **V3-DEPCLOSURE-001 is the blocker.**

---

## V3-DEPCLOSURE-001 — Closure over the existing Solidity dependency graph, earned not declared

- **Objective:** `DevelopmentCorpusManifest.dependency_closure` is `Literal["NOT_ESTABLISHED"]`
  (`src/mmaudit/models/development_corpus.py:99`) and `const "NOT_ESTABLISHED"` in all 22
  emitting schemas. The product cannot express that a manifest is closed under dependency, so every
  audit it performs reasons about each file with its dependencies absent.
- **What already exists and must be reused:** `src/mmaudit/solidity/graphs.py` already builds a
  per-tree graph with `SolidityGraphKind` edges `INHERITANCE`, `EXTERNAL_CALL`, `DELEGATECALL`,
  `LOW_LEVEL_CALL`, `INTERNAL_CALL`, `STATE_READ`/`STATE_WRITE`/`STATE_DEPENDENCY`
  (`src/mmaudit/models/schemas.py:1226`), each edge carrying `path`, line range, `source_hash`,
  `confidence` and `provenance`. `src/mmaudit/solidity/retrieval.py` compacts and ranks it by
  role. **Neither module is imported anywhere in `development_cli.py`,
  `models/development_corpus.py` or `orchestration/development_corpus_ensemble.py`.** The
  closure primitive is built; it is not wired to the audit path.
- **Why textual import closure is not enough (and is not what this ticket asks for):** in this
  codebase a controller calls its reserve through an interface —
  `IReserveManager(reserve).backingValue()` — so the import closure of `MintRedeemController.sol`
  contains `IReserveManager.sol` and stops. The model still cannot see what `backingValue()` does.
  A closure that stops at interfaces would let the product declare `ESTABLISHED` while the model
  is still blind to the code that decides the finding. Closure must follow `EXTERNAL_CALL` and
  `DELEGATECALL` edges through to in-tree implementers of the interface (via `INHERITANCE`
  edges), not stop at the import.
- **Observed consequence of the gap:** 68 of 317 claims (21%) state in their own text that a
  dependency was not supplied; 37 of those were marked `SUPPORTED` by both reviewers, who were
  blind to the same code. The run's highest-severity claim (`bsc ReserveManager.sol:524-531`)
  carries its own falsification condition in an unreviewed library.
- **Files/modules:** `src/mmaudit/models/development_corpus.py`; `dependency_closure` in all
  emitting schemas via `scripts/generate_release_schemas.py`; a thin adapter from
  `solidity/graphs.py` output to manifest membership; focused unit tests.
- **Acceptance criteria:**
  - `dependency_closure` gains values that are **earned by computation, never declared**. The
    engine builds the graph over the supplied tree, computes the closure of each primary under a
    named edge set, and records the edge set, the graph digest and the exact member paths. A
    manifest whose declared value disagrees with the computation is refused.
  - Two distinct levels, so the field can never be read as more than it is:
    `IMPORT_CLOSED` — every `import` of every member resolves, via the existing remappings parser
    (`solidity/projects.py:320`), to a member; and `CALL_CLOSED` — additionally every
    `EXTERNAL_CALL`/`DELEGATECALL` target type has all its in-tree implementers as members. Any
    unresolved edge, any `confidence` below a policy threshold, or any parse failure yields
    `NOT_ESTABLISHED` with the exact shortfall recorded. Fail closed.
  - Existing single-file manifests stay valid and keep reporting `NOT_ESTABLISHED`. No historical
    artifact is rewritten; schema hashes change only through the generator with the change
    recorded.
- **Explicitly out of scope:** compilation, deployment wiring, reachability, off-tree
  dependencies (OpenZeppelin etc. are recorded as off-tree edges, not silently dropped, and block
  `CALL_CLOSED` unless supplied).
- **Dependencies:** none. Provider-free.

## V3-CONTEXTSRC-001 — Context sources, and corpus-level coverage so nothing is silently skipped

- **Objective:** `DevelopmentCorpusPlan.exact_selected_partition_and_estimates`
  (`development_corpus.py:326`) requires one shard per manifest source, so every dependency added
  for closure becomes a paid primary in every manifest that includes it. Closure is unusable
  economically without a context-source class.
- **Prompt side needs no change:** `_PROTOCOL_SYSTEM_PROMPT` (`:397`) already instructs the model
  to use *"the complete selected local source snapshot as context"* and not to *"assume missing
  dependencies"*. The model is already told to read context it is currently never given.
- **Acceptance criteria:**
  - The manifest carries context sources distinct from primaries, hashed, bounded by the same
    limits, included in `manifest_sha256`, addressable as `root_cause_ref` origins, never sharded,
    never separately charged. Closure in V3-DEPCLOSURE-001 is over primary ∪ context.
  - **Coverage is recorded at corpus level, not manifest level.** A file that is only ever a
    context source has never been audited. The engine must emit, for a set of manifests over one
    tree, the exact set of paths that were a primary in a complete observation and the set that
    were not. An automated run over a tree that leaves any in-tree file un-primaried is not
    complete and must say so.
- **Dependencies:** V3-DEPCLOSURE-001.

## V3-AUTOPARTITION-001 — The engine derives manifests from a tree; the operator does not

- **Objective:** the 125-file run was partitioned, sized and ordered by an operator script, and
  the 1800 s `--maximum-run-seconds` cap (`development_cli.py`) bounds candidate plus both
  reviewer legs across all shards of a manifest — observed single-file elapsed times were
  180–690 s, so any closure-bearing manifest of more than a handful of files cannot finish. Raising
  the cap is the wrong level. A fully automated auditor takes a tree and a budget and produces the
  manifests itself.
- **Acceptance criteria:**
  - Input is a tree root, a remappings source and a policy. The engine builds the graph, computes
    per-file closures, partitions the tree into manifests each satisfying `CALL_CLOSED` (or records
    exactly why one cannot), and schedules shards under the whole-run policy — resumable across
    invocations with the existing request-id identity, so a stopped run continues rather than
    restarts.
  - Plan-time refusal: a plan that cannot finish within its budget or run-seconds is refused
    before the first paid call, with the shortfall stated. Never a refusal discovered at shard 40.
  - The 1800 s cap may stay; it becomes a per-manifest bound the partitioner respects, not a limit
    the operator works around.
- **Dependencies:** V3-DEPCLOSURE-001, V3-CONTEXTSRC-001.

## V3-DEVRETRY-001 — Transient failures retried by the engine, not by the operator

- **Objective:** the development ensemble path hardcodes `"maximum_attempts": 1`
  (`development_cli.py:383`, `:504`, `:678`, and the ensemble-manifest policy) even though
  `DevelopmentCostPolicy.maximum_attempts` already permits 1–32
  (`models/development_costs.py:83`) and the budget arithmetic already multiplies by it (`:239`).
  Completing the 125-file run took **eight operator-driven passes** to clear 23 failures whose
  causes were HTTP 429 (17), candidate truncation (4), timeout (1) and unparseable structured
  output (1). None required judgment; all required a human.
- **Acceptance criteria:**
  - Same-route retry with backoff for 429/timeout, and raised-ceiling retry for truncation, under
    `maximum_attempts` and the existing per-attempt/total budget — each attempt a distinct ledger
    reservation with its own identity; no attempt reuses a request id.
  - A structured-output rejection (`INVALID_RESPONSE`) is retried on the same route at least once
    before being recorded as a failure. `V3-DEVDECODE-001` correctly made rejection evidence
    unrepairable; this ticket adds a fresh attempt, not a repair.
  - The observation records every attempt, so a "clean" result reached on attempt 3 is
    distinguishable from one reached on attempt 1. First-attempt-only scoring
    (`V3-RETRY-001`'s principle) is preserved.
- **Dependencies:** none. Provider-free.

## V3-LEGDIVERSITY-001 — No two ensemble legs on one provider; lineage independence recorded

- **Objective:** every result artifact in the run carries `lineage_independence:
  NOT_ESTABLISHED` — the field is `Literal` in `models/development_corpus_ensemble.py:66,294` and
  `development_ensemble.py:94,299`, so the development path cannot record it even when true. And
  the run rotated through four providers by hand because transient 429s followed whichever provider
  was driven hardest; with two legs on DeepInfra, one provider's transient capacity failure took out two-thirds of the
  panel.
- **Acceptance criteria:**
  - Endpoint selection for an ensemble refuses two legs on the same provider unless the operator
    overrides explicitly, and records the provider set.
  - `lineage_independence` gains an earned value: distinct model authors **and** distinct
    providers across all legs, computed from the frozen endpoint snapshots, never declared.
    Same-author legs (e.g. two GLM variants) can never earn it.
- **Dependencies:** none. Provider-free.

## V3-REFUSALDIAG-001 — One refusal message for every distinct cause

- **Objective:** `development_cli.py:902` and `:1081` wrap the whole command body in
  `except Exception:` and emit a single fixed string, then `raise typer.Exit(...) from None`,
  discarding the cause.
- **Observed consequence:** three separate defects in one session presented identically. Two were
  misreported to the operator as budget/headroom problems until the real cause was recovered by
  monkeypatching `typer.echo` to print `sys.exc_info()` from inside the except block. Actual
  causes: a duplicate ledger request id; `prepare_owned_empty_directory` rejecting a symlinked
  parent (`/tmp` on macOS); a genuine headroom refusal.
- **Acceptance criteria:** the operator-facing summary may stay as it is. The exception type and
  message are additionally written to a retained diagnostics record in the run's output custody,
  with existing secret redaction applied; no traceback path may leak a credential or private path.
  One regression test per distinct refusal cause, asserting they are distinguishable.
- **Dependencies:** none.

## V3-RUNIDREUSE-001 — Duplicate request id is refused as a cost problem

- **Objective:** `run_development_corpus_ensemble`
  (`orchestration/development_corpus_ensemble.py:404-417`) correctly refuses `e.request_id in
  requests`, but raises the same `"manifest ensemble refuses cumulative costs or headroom"` as a
  budget refusal. The id derives from `run_id` + `manifest_sha256`
  (`development_corpus_request_id`, `development_corpus.py:277`), so retrying with the same
  `--run-id` always hits this and reads as a budget fault.
- **Acceptance criteria:** a distinct refusal naming request-id reuse and the colliding id. The
  guard does not weaken. Becomes moot for the automated path once V3-DEVRETRY-001 assigns attempt
  identities itself, but the manual path still needs the message.
- **Dependencies:** V3-REFUSALDIAG-001.

## V3-COSTUNKNOWN-001 — Provider rejections carried at full reservation

- **Objective:** an HTTP 429 is recorded `uncertain_accounted` at the full reserved amount. Over
  the run: 32 uncertain rows totalling $43.25 against $16.47 settled — **72% of reported spend
  unconfirmed** — every row with `actual_cost_usd: null`.
- **Evidence:** all 17 archived 429 observations have `generation_id: None` and
  `reported_cost_usd: None`. No generation was created.
- **Acceptance criteria:** where the engine's own recorded evidence shows a provider rejection
  with no generation identity and no usage, reconcile at zero and record the basis. A response that
  *did* create a generation identity keeps the conservative carry. The reserve-then-reconcile
  invariant and the refusal to assume an unsent request are preserved; this narrows the uncertain
  class using evidence already captured and must not become a general "zero on error" path.
- **Decision required before adoption, not Codex's to make:** this rests on OpenRouter not billing
  a request it rejected with 429 and no generation id. That is the documented behaviour but it has
  not been verified against an invoice in this session. Jos should confirm it, or the ticket
  should require a `/generation`-style confirmation call before settling at zero.
- **Dependencies:** sequence last; it touches the ledger.

---

## Audit of the first draft — what was wrong and what was missing

1. **Material error — DEPCLOSURE-001 asked for a textual import resolver.** The tree already has a
   call graph with the exact edge kinds closure needs, unused by the audit path. A textual
   closure would also stop at interfaces and produce a false `ESTABLISHED`. Rewritten to wire the
   existing graph and define two honest levels.
2. **Omission — coverage.** Context sources that are never a primary are never audited; without a
   corpus-level coverage record an automated run could silently skip files. Added to CONTEXTSRC.
3. **Omission — automation of partitioning.** "Raise the 1800 s cap" was the wrong level; the goal
   is a tree in, manifests out, resumable. RUNSECONDS-001 replaced by AUTOPARTITION-001.
4. **Omission — retry.** Eight manual passes is the opposite of automation, and the policy model
   already supports `maximum_attempts` up to 32; only the CLI hardcodes 1. Added DEVRETRY-001.
5. **Omission — provider and lineage diversity as engine properties.** Hand-rotating providers is
   not a method. Added LEGDIVERSITY-001.
6. **Overclaim — COSTUNKNOWN-001 stated the zero-cost conclusion as settled.** It depends on
   provider billing behaviour not verified here; marked as a decision for Jos.

Not raised as tickets, noted for the roadmap: cross-chain differential audit (the engagement's
central question — ETH vs BSC divergence — was answered by seven Claude reviewers reading both
trees, not by the engine, which audited each chain blind to the other); and the `CANDIDATE_INCOMPLETE`
class for files whose candidate response exceeds 65,536 tokens, which needs sharding within a
file, not a higher ceiling.
