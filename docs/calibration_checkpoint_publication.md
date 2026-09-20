# Source-owned calibration checkpoint publication

This adapter binds a population phase to its exact local transparency history.
It does not authenticate that history, publish anything by default, or issue a
chain, time, native measurement, qualification or release capability. The
[external seal review](remediation/v3/external_seal_verification_review.md) explains
why the previous population-only commitment was insufficient for this binding.

## Explicit new meaning

`CalibrationCheckpointSubject` is a new canonical envelope with artifact kind
`CALIBRATION_CHECKPOINT_SUBJECT` and profile
`CALIBRATION_TRANSPARENCY_CHECKPOINT_V1`. It binds the original population subject
digest, registration event, phase, full original inclusion/extension proof and
exact checkpoint. Measurement also binds the original registration envelope's
digest and must extend that envelope's exact checkpoint and complete leaf prefix.
The caller must supply the exact expected checkpoint hash; a valid alternative
history cannot silently substitute for it.

The file submitted for timestamping is the 32-byte binary digest of this new
envelope. Its SHA-256 is combined with a fresh owned 16-byte nonce using the
existing calendar convention. The envelope's domain is distinct from the old
population subject. Old public population entry points reject the new type, and
old receipts and schemas keep their original meaning. A checkpoint hash is not
interchangeable with its text encoding, file hash or population hash.

## Source ownership and durable layout

`prepare_calibration_registration_checkpoint` and
`prepare_calibration_measurement_checkpoint` in
`orchestration.calibration_checkpoint_publication` reuse the original population
and native-measurement preparers. The latter still requires the actual live
measurement, original proof, original ledger and exact registration population.
An isolated test verifier or a reopened data receipt is not production custody.

Each new output is a separate private directory:

| Path | Retained meaning |
| --- | --- |
| `source/` | Original population subject and original source preparation; its legacy calendar stays PREPARED-only and is never dispatched by this publisher. |
| `checkpoint.json` | Canonical new envelope, bounded to 2,000,000 bytes. Existing population and proof bounds remain unchanged. |
| `publication.json` | New `CALIBRATION_CHECKPOINT_CALENDAR_PUBLICATION` descriptor, binding the original source preparation, envelope file, predecessor descriptor and actual calendar preparation. |
| `calendar/` | Original locked journal containing the fresh checkpoint nonce, request, dispatch intent and outcomes. |

The source, envelope, descriptor and nonce are retained before the one allowed
checkpoint POST. The caller must retain the descriptor hash outside this output
for recovery. Neither the full subject, checkpoint preimage nor unmasked digest
is sent to the calendar. There is no default origin or contact permission.
Explicit contact authorization for a future selected run is still required.

Original producer identity/code, source objects, borrowed proof bytes, ledger,
private file inodes and complete predecessor history remain checked through the
await and every enclosing cleanup. New outcome-file custody is captured from the
original journal before close, not reobserved as a replacement afterward. A
concurrent extension of the predecessor calendar history also refuses the active
measurement handoff. The prepared context must finish successfully; a recorded
reply can survive a later source or cleanup refusal without making that handoff
successful.

## Explicit actual-batch checkpoint profile

`calibration_calendar_controller.execute_checkpoint_recorded_calibration_measurement`
joins this publisher to the original registered batch and live native measurement
owners. Its distinct `CheckpointRecordedCalibrationResult` cannot be confused with
the existing population-only entry/result. Existing entrypoints and defaults are
unchanged; selecting this function does not authorize calendar or model contact.

The caller supplies an explicit log ID and exact original initial proof/checkpoint
pin, or an explicit `None` pair for a fresh log. The controller freezes that input
before registration and reserves space for both phase leaves within the existing
10,000-leaf limit. A caller-chosen initial tip is data, not an authenticated accepted
history; a fresh-log request does not establish that no prior history exists.

The actual original registration subject is appended before any model preflight.
Its checkpoint is recorded using the original once-only publisher. While the
original native measurement proof is live, the actual complete measured-population
subject is appended to that exact registration checkpoint and recorded separately.
No fixture summary, shortened population or caller-supplied measured subject can
substitute. The original preflight, native proof, accounting and release predicates
remain mandatory. Both policy output and numeric-support refusal retain their
original meaning.

The same task/process/deadline-bound lifecycle checks original initial-tip bytes,
phase files and full original outcome histories across awaits, native disposal and
final population/receipt/ledger readback. A failed or uncertain operation stops;
GET recovery cannot resume the batch. A late outer refusal can leave recorded
phase or native receipt files without making the controller successful.

Two boundaries remain distinct. Conflicting checkpoint commitments can both be
included in one aggregate root; inclusion does not choose the accepted log history.
Also, the measured subject ends at `RUNNER_RETAINED`, before native revocation,
terminal cleanup and the completion receipt. A surviving checkpoint is not proof
of successful completion. The [updated seal review](remediation/v3/external_seal_verification_review.md)
records paired synthetic counterexamples and the external-verification contract.

## Scoped native-to-terminal completion

`checkpoint_calibration_completion_scope` follows the same actual checkpoint
batch, with the same required inputs and unchanged contact defaults. It yields
an opaque `OwnedCheckpointCalibrationCompletion` only after original native
revocation, runner/accounting disposal and successful terminal receipt, journal,
phase-file and final-ledger checks. Exact native input identities and bytes are
retained while the original proof is still live; that proof is never revived.

`observe_checkpoint_calibration_completion` returns the original detached result
only while that handle remains valid in its original task, process and deadline.
Checks cover the original initial tip, native inputs, result objects, phase/outcome
files, terminal receipt/event and final accounting. They continue across consumer
awaits and through timeout-manager and secret cleanup. Any observed custody fault
invalidates the handle irreversibly, even if the caller restores the changed data.
Exceptions, cancellation, timeout and every scope exit invalidate it as well.
The consumer must observe the handle at its use boundary and the entire scope must
exit successfully; an earlier observation cannot excuse a later refusal.

The handle is not constructible, copyable or serializable. Fresh-process readers
still return data and cannot recreate it. The two existing execute APIs retain
their signatures, defaults and detached-result meaning. The completion scope does
not supply an external seal, authenticated accepted history/chronology, a native
proof, policy adoption, qualification, release or paid permission. It closes only
the original native-to-terminal ownership gap; the external-verification contract
and every existing gate remain required.

## Recovery and limits

`load_calibration_checkpoint_publication` returns constructible data.
`recover_calibration_checkpoint_publication` uses GET only at the original
commitment and explicitly supplied origin retained in the descriptor. The inner
checkpoint recovery API borrows the original locked journal through an async
context; the source publisher retains its full outcome custody across that close.
Recovery works in a fresh process after original-source loss but cannot recreate
native authority, submit a second POST or resume the original batch.

Abandoned PREPARED-only journals, malformed/partial tails, links, replacements,
noncanonical bytes, wrong pins and extra files refuse without truncation, repair
or automatic retry. Some invalid inputs or write failures can leave a private
incomplete output; it is not dispatchable and cannot be silently reused. All
authority flags remain false, including after a fully replayed response.

The old batch entry still records its population-only profile; the checkpoint
profile must be selected explicitly. Selection of an authenticated external
history/chain source, pre-dispatch chronology, independent
reproduction, external seals and native policy/release adoption remain required.
No real calendar, Bitcoin node, paid provider, upstream executable or external
trust profile was used or adopted by this provider-free slice. Local synthetic
checks are not upstream conformance or evidence of a completed audit.
