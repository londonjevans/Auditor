# External seal verification acceptance review

Status: source-only engineering review under `V3-CALIBRATE-001`, 2026-09-10.
This does not adopt OpenTimestamps, select a chain/node/calendar, authorize contact,
or issue an external seal. The parent ticket remains incomplete.

## Outcome

The explicit checkpoint-profile controller now binds each actual population phase
to its exact transparency checkpoint/history. Its source-owned publisher and
actual registered/native batch integration are locally tested. The original
population-only entry and receipt semantics remain unchanged; the historical
subject/checkpoint counterexamples below still apply to that old profile.

The remaining gap is not another checkpoint hash. Two conflicting checkpoint
views have different commitments, yet both commitments can be included in the
same aggregate Merkle root. Verifying inclusion in that root would not choose a
single accepted log history. Separately, the measured checkpoint precedes native
proof disposal and terminal completion. A recorded checkpoint may survive a later
cleanup/accounting refusal; its existence does not attest successful completion.

These are limitations of the explicit **recording-only** APIs, not a
demonstrated bypass of its gates. Its outputs correctly remain nonauthorizing.
Do not promote that API into a seal issuer without closing the bindings below.

The frozen objective's clause 2 requires external constructed/public truth,
cross-lineage independence, and an externally anchored append-only seal verified
by independent rerun and inclusion proof. These are conjunctive. Neither a second
timestamp lookup nor a locally rebuilt comparison is the independent audit rerun.
The existing pre-dispatch anchoring requirement is not waived by this review.

## Supplied-source findings

Reference inputs are the operator-staged, ignored files identified in
[the replay note](../../opentimestamps_replay.md#reference-and-provenance): library
revision `3af46432efc4a4c4e7bba439c1f49bce808eb3e5`, client revision
`cd71c7609421bed2a07b9642a3c02a58c9fd2cdf`. These are local provenance observations,
not independently authenticated upstream checkouts. Nothing was copied, imported,
installed or executed from those reference trees.

| Local reference location | Observed behavior | What it does not establish |
| --- | --- | --- |
| `client/cmds.py:211`, `is_timestamp_complete` | A Bitcoin-attestation tag makes the proof "complete" for the client's upgrade loop. | Validity of the claimed block, its height or its Merkle root. |
| `client/cmds.py:385`, `verify_timestamp` | Upgrades first, asks the configured node for height/hash/header, compares the calculated commitment, and stops after one successful Bitcoin attestation. | An independent chain verifier, confirmation policy, or agreement of all branches. |
| `opentimestamps_core_notary.py:279`, `verify_against_blockheader` | Checks digest length and equality to the supplied header's Merkle root, then returns its time. | Origin or accepted-chain membership of that header; precision of an audit dispatch time. |
| `client/cmds.py:221`, `upgrade_timestamp` | Merges cache and permitted calendar responses; pending URIs can select remote calendars through the whitelist. | An offline-only operation or independently authenticated cache contents. |
| `client/args.py:37`, common options and `setup_bitcoin` | Exposes calendar whitelist/cache/network/node settings and delegates RPC setup. | Permission to use ambient configuration, credentials, public infrastructure or a selected trust profile in this repository. |
| `opentimestamps_bitcoin.py`, `make_timestamp_from_block` | Constructs a proof from a supplied block and checks its reconstructed Merkle root. | A header-chain or full-chain consensus implementation. |

In particular, do not execute the upstream `verify` command as an "offline
diagnostic": its inspected call path can upgrade through calendars before node
lookup. No such execution occurred here.

The operator's "own node is the only way" conclusion is not established by these
files. The inspected client delegates to a node; that does not prove every possible
verification architecture must do so. Equally, loopback location does not prove
the responding process or its chain state is trustworthy. A header-only design
would need a specified assurance boundary; it must not silently claim full-chain
consensus equivalence. No such alternative is implemented or selected here.

## Exact remaining acceptance boundaries

These are requirements for completing the existing seal path, not additional
qualification thresholds or a relaxation of current gates.

| Boundary | Current authoritative evidence | Required completion evidence |
| --- | --- | --- |
| Subject and log-checkpoint binding | Locally implemented by `CalibrationCheckpointSubject`, the original-source checkpoint publisher and `execute_checkpoint_recorded_calibration_measurement`. Exact phase/checkpoint/predecessor inclusion is retained through the actual batch. The old population-only profile remains distinct. | Preserve this binding in any future seal consumer; do not treat an old population stamp as a checkpoint stamp. Binding is not accepted-history or chain authentication. |
| Accepted append-only history | The controller freezes an explicit caller-supplied initial tip/pin or fresh-log None pair. Full-prefix validators check the supplied view, not which view was previously accepted. | Independently anchored checkpoint identity plus exact consistency with the original previously accepted checkpoint, and a linearized acceptance transition for the selected log/scope. A caller cannot choose an older/forked tip or silently reset history. Inclusion of competing views does not elect one; detecting a conflict must not silently bless either. No claim of globally proving the absence of all forks is made. |
| Chain/header source | The staged notary compares against a caller-supplied header; the staged client delegates header selection. | A specified, authenticated source of accepted-chain membership, with explicit network/consensus, freshness, confirmation and reorganization handling. Parser success, a node URL, a local header file, or a self-hash cannot substitute for that source. |
| Proof compatibility | The local reader deliberately supports a bounded SHA-256 subset. Two supplied proofs replay as data; five are refused for unsupported profile operations/hash types. | Compatibility evidence for the selected actual publication profile, including genuine invalid-anchor rejection using an authenticated header source. Unsupported-profile refusal of `bad-stamp.txt.ots` is not that test. No requirement to enable unrelated algorithms is inferred. |
| Pre-dispatch chronology | The recording hook persists and contacts a calendar before preflight, but accepts pending/opaque data as recordings. | Original source custody of independently verified registration anchoring before the guarded dispatch boundary, bound to this full population and request. Neither event numbering, a POST intent, a node clock, nor two equal block-height claims establishes that ordering. |
| Measurement, terminal completion and independent rerun | The measured checkpoint contains the `RUNNER_RETAINED` prefix. Native proof revocation, original runner/accounting disposal, `FINISHED` and completion receipt follow it. The controller checks these later conditions before returning data; the seal issuer is absent. | A source-owned handoff from live native evidence through clean terminal completion, followed by the external-seal/reproduction join. Freeze the original completion receipt/event and final ledger identity/snapshot alongside the exact measured checkpoint. Reloaded JSON cannot recreate revoked native authority; a phase stamp cannot replace the terminal checks. |
| Authority lifecycle | Durable data flags remain false; there is no production external-seal issuer/consumer completing the path. | A source-owned issuer and downstream consumer which require every above predicate and preserve original native disposal, refusal and release behavior. No Boolean, mock verifier, arbitrary callback or synthetic chain source may enable it. |
| Operational admission | The operator report grants no publication, node/client installation, protocol/trust adoption or paid run. Unknown prior billing still blocks authenticated reservations. | Separate authority for any necessary external operation, and satisfaction of the original per-call reservation/reconciliation/ceiling stops. Reading a reference or implementing a local adapter supplies neither. |

A calendar may be an untrusted delivery mechanism when a separately authenticated
anchor proves the exact commitment. Do not add an unnecessary rule requiring the
calendar itself to be the authority. The security question is what authenticates
the selected log statement and chain inclusion; transport origin restrictions
still control where this application is permitted to send requests.

## Historical subject-only counterexamples

`tests/unit/test_calibration_external_seal_boundary.py` uses only existing isolated
synthetic publication data and the independent fixture
`tests/fixtures/opentimestamps/synthetic_external_seal_boundary.json`.

1. Fork before registration or between registration and measurement: both complete
   local comparisons are internally valid under the same claimed log ID, but their
   final checkpoints differ. The existing subject-stamping requests are identical.
   A local comparison of checkpoint commitments distinguishes the fork, illustrating
   the missing preimage binding without implementing or adopting a new publisher.
2. Cross the registration proof from one earlier fork with measurement from the
   other: the original comparison refuses. This paired control preserves the
   existing local consistency invariant; neither individually valid fork gets
   external authority.
3. Two distinct synthetic commitments replay through append/prepend paths to the
   same calculated root and claimed height. This contains no header, observed
   publication time or dispatch evidence, and cannot put a dispatch between them.
4. Change only the claimed height: the proof bytes and attestation payload hash
   change, while the calculated root does not. The height must be checked against
   an authenticated external source; replay is not such a check.

These are binding/order counterexamples, not real Bitcoin proofs, upstream
conformance results, malicious external submissions or evidence of paid execution.
No chain time, work, confirmation, economic security or protocol deployment is
simulated as authority.

## Checkpoint-profile acceptance counterexamples

`tests/unit/test_checkpoint_seal_acceptance.py` adds paired local controls using
the existing isolated synthetic population/native fixtures. Socket connections
and subprocess execution are forbidden; calendar exchanges use MockTransport.

1. Fork before registration or after a shared registration. Both checkpoint views
   validate internally and bind the same measured population under the same log
   ID, but have different exact checkpoint envelopes and calendar requests. Two
   independently assembled append/prepend/SHA-256 paths reach the same calculated
   aggregate root and claimed height. This proves only the data-level possibility
   of including both views; no real header or accepted chain is supplied. An
   authenticated root would still need a separate accepted-history transition.
2. Supply the competing checkpoint's pin with the original proof: the existing
   exact-pin validator refuses. The new review preserves the implemented binding;
   it does not demonstrate a gate bypass or justify weakening it.
3. In the actual checkpoint batch lifecycle, observe the measured checkpoint while
   native verification remains live and the completion receipt does not yet exist.
   After disposal, the native verifier refuses the original proof. A clean run
   completes; adding a synthetic unknown liability at final readback makes the
   original controller refuse. In each case its recorded measured checkpoint stays
   byte-identical and readable as nonauthorizing data. Its subject ends at
   `RUNNER_RETAINED`, not `FINISHED`. A surviving stamp cannot replace terminal
   ownership, accounting or successful completion.

## Native lifetime and independent reproduction

The source order is material:

```text
original registration checkpoint and recorded reply
  -> original preflights and candidate/primary/replay executions
  -> measured checkpoint while native verification is live
  -> native verification revoked; original runner/accounting owners disposed
  -> FINISHED/CONSUMED and original completion receipt
  -> controller rechecks original phases, native files, population and final ledger
  -> detached recording result (not a seal)
```

`authenticated_calibration_openrouter._owned_registered_calibration_scope` owns
registration, the preflight boundary and terminal population event.
`authenticated_calibration_measurement._build_registered_measurement_scope` owns
native verification, revokes it in `finally`, and creates the receipt only after
original cleanup. The controller's original completion checks bracket its final
recording readback. The review does not move or waive any of those checks.

There are distinct kinds of "replay". Calendar proof replay recomputes hash paths.
`build_authenticated_evidence_seal_runner_inputs` instead consumes live original
AUTHRUNNER and frozen-truth custody, derives lineages, and checks exact original
request/cost/report joins. `EvidenceAuthoritySubject` requires different report
evidence and distinct primary/replay runner roots with equal deterministic
decision projections. That is not a requirement for byte-identical raw model
responses. Neither two calendar GETs nor two JSON loads satisfy these predicates.
Independent J2 qualification remains separate from calibration and policy adoption.

`validate_authenticated_calibration_successor_release_inputs` checks proposed
P1/C1/P2/C2 against an original trusted source-release observation. It explicitly
returns a nonauthorizing transition and does not consume an external seal. Adding
a valid timestamp alone would not complete this native policy/release boundary.

## Exact external-verification input contract

No chain verification architecture is adopted by this review. Before implementing
an actual authenticated-chain consumer, the selected architecture must supply the
following, not just plausible response fields:

| Required contract | Evidence needed before it can grant credit |
| --- | --- |
| Chain and verifier identity | Exact selected network/consensus and implementation identity, with the source and parameters needed to validate its declared assurance boundary. A log ID, URL or hash of a locally authored file is insufficient. |
| Authenticated accepted state | Source-owned observation of which chain/tip the verifier accepts, binding the requested height to the returned block identity and Merkle root. A coherent header supplied by an arbitrary caller is not accepted-chain evidence. |
| Freshness and reorganization | Explicit frozen policy for observation freshness, confirmation depth, stale/unavailable state and reorganization/conflict handling. Required observations must remain valid through acceptance/consumption; an error or missing history is not a pass. This review invents no numeric threshold. |
| Proof/profile compatibility | Bounded exact original checkpoint/nonce/request/proof bytes joined to that authenticated root. Offline positive and genuinely invalid-anchor vectors for the selected profile, including wrong network/height/block/root, stale views and competing histories. Unsupported-operation refusal is not invalid-anchor verification. |
| History acceptance | Original prior accepted checkpoint and a single owned update boundary for the selected log/scope; consistency, conflict, rollback and recovery rules. A second valid branch cannot silently become the new baseline. Fresh-log data is not evidence that no accepted history exists. |
| Causal dispatch and completion | The original registration anchor must be verified before the guarded dispatch, not inferred later from block-time comparisons. Preserve original measured/native/terminal custody until the final seal/reproduction consumer finishes. GET recovery remains data-only unless a separate authenticated lifecycle is actually implemented. |

For a node-backed architecture, the missing input is a specified authenticated
node-service/ownership contract and safe local evidence for that contract. Loopback
location alone does not authenticate a responder or its chain state. For an
independent header/chain verifier, the missing inputs are pinned validation source,
consensus parameters and deterministic offline vectors, including the explicit
limits of header-only verification. Do not claim full-chain equivalence from a
header parser. The staged OpenTimestamps client supplies neither architecture.

## Next bounded implementation and missing inputs

Checkpoint binding and actual batch integration are now locally implemented.
The next available local implementation is the original native-to-terminal
completion handoff: retain the exact live native inputs before revocation, refuse
every cleanup/accounting failure, and complete the handoff only after the original
terminal receipt/event, phase files and final ledger have been revalidated. It must
remain source-owned and nonauthorizing until an actual authenticated external-seal
consumer exists; no reopened data, public Boolean or arbitrary verifier callback
may recreate it. Preserve existing recording results, disposal and GET-only recovery.

That ownership work does not require a public call or a chain/trust choice. It also
does not close chain authentication. Before implementing the latter, the missing
input must match the selected verification architecture: either a specified and
authenticated node-service contract with safe local test evidence, or pinned
header/chain validation source, consensus parameters and deterministic offline test
vectors for an independent verifier. Staging more OpenTimestamps calendar code or
only a header deserializer would not resolve that gap. Do not provision a node,
read RPC credentials, select mainnet, or make a public lookup to work around it.

The current cost policy is unchanged. `OP-COST2026-09-09` remains an **explicit
operator relaxation of a stricter internal cost rule**, not a discovery that the
rule was wrong; it does not relax lineage, qualification, seal or release gates.
