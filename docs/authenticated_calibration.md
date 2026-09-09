# Native authenticated calibration

This is a signer-free, in-process measurement and policy-proposal API. It is not
a production qualification, a release authorization, or a complete calibration
campaign controller. The existing signed legacy format and numeric projection
remain separate and compatible.

## Input and evidence contract

`mmaudit.models.authenticated_calibration.observe_authenticated_model_calibration`
requires the exact sorted selected model IDs, the frozen benchmark suite and live
`VerifiedFrozenGroundTruth`, and one `AuthenticatedCalibrationCandidateInputs` per
selected model. Every candidate input must contain original, still-live
`VerifiedCrossLineageRunnerCustody`, its configuration-bound runner evidence, and
all original primary/replay custody objects. Missing, synthetic, revoked or
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

## Campaign integration still required

The selected-ID tuple is not a precommitted campaign registration. A controller
must freeze and cover the full intended population before dispatch, retain every
failed/incomplete attempt and liability, and enforce the USD 250 ceiling before
calls. Retained-cost validation is not global budget admission. It counts prior
spend once per unambiguous closed ledger chain, sums distinct ledgers, and rejects
cost at or above USD 250; it does not discover unrelated external ledgers.

Two existing lifecycle boundaries must be handled explicitly before that
controller is usable:

- The current OpenRouter runner adapter revokes its runner and child capabilities
  before returning. Re-reading its serialized bundle cannot recreate custody.
- A live closed-runner ledger capability requires its exact final snapshot.
  Advancing the shared ledger invalidates the earlier closure. Structural chain
  measurement does not bypass that requirement. A dedicated campaign-owned
  custody/immutable-prefix handoff, or an equivalently integrity-preserving
  accounting design, is required; simply looping the current CLI will not work.

The local suite exercises real frozen-truth resolution and actual disposable
ledger behavior. Isolated lifecycle stand-ins test the lease state machine, and
the production consumer explicitly rejects their objects. None of these tests
establishes positive REAL-provider campaign authority. That integration, an
externally anchored reproducible seal, successor P2/C2 release admission and an
independent qualification campaign remain unfinished under `V3-CALIBRATE-001`.
