# Exact historical uncertainty allowance — September 11, 2026

Jos's direct conversation instruction authorizes one explicit relaxation of the
operator reservation policy: the two named pre-policy uncertain rows may stop
blocking new reservations under `unknown_billing_blocks_new_work`.

| Historical request scope | Reserved USD | Accounted USD |
|---|---|---|
| `authrunner.smoke.r17.judge.replay` | 0.18105 | 0.18105 |
| `authrunner.smoke.r2.candidate.primary` | 0.05225616 | 0.05225616 |

This is an operator relaxation of the prior rule, not a correction of supposedly
incorrect enforcement. It does not settle either bill or establish that its actual
cost is known. Both rows retain `uncertain_accounted`, null actual cost, original
identity/timestamps and their full combined USD 0.23330616 liability. No historical
ledger row may be rewritten, reconciled, released or removed by this work.

The allowance binds each complete request ID, reservation ID, canonical UTC
creation/update timestamp, status, reserved/accounted values and null actual cost.
The pair is ordered, self-hashed and restricted to these exact request scopes and
amounts, with timestamps predating the September-9 policy. A prefix or pre-policy
date alone never grants an exception. A different reservation, selection suffix,
attempt, timestamp or amount does not match.

Policy schema 1.1 carries this explicit allowance; schema 1.0 retains its existing
bytes and behavior. `unknown_billing_blocks_new_work` remains true. All four atomic
checks—reserve, portfolio claim, active-reservation recovery and transport commit—
repeat exact matching under the existing ledger lock. Every other or future
uncertain row still blocks. Every selected smoke role must permit the exact rows;
one role's exception cannot override another role's stricter policy.

Actual-bill reconciliation for new calls, reservation-overrun stops, the fixed
ceiling inside USD 250, no automatic ceiling increase, cost-baseline recovery,
qualification, independent lineage, privacy, seal and release gates remain intact.
No provider call, credential use, new ledger or paid execution is authorized.

## Current implementation boundary

The operator's September-11 08:59Z report supplies both complete rows. Its full
SHA256 is `875e435ce45b603b7419726bfa80362952ac8ab0434fad5bfd154646adb67e81`.
The report is nonauthorizing evidence; Jos's direct instruction supplies the
precise allowance authority. No private ledger has been inspected or changed.

The active plan is now the exact authenticated v1.11 cost-only successor. Opaque
ancestry replay reconstructs its exact v1.10 predecessor (raw hash
`95b136f0f2254c84ada3391eead1aeee9a52bd88f60ce78d4cd88bd42ed7be59`), including
the original September-9 transition, before applying this separately identified
`OP-COSTLEGACY-2026-09-11` relaxation. It accepts no caller-selected allowance rows.
The old v1.10 derivation and default policy remain byte-for-byte reproducible.

Active plan raw SHA256:
`7af8d0eeeade437767c965482c563dafa893ce76eee818333fd728daab7cdbb0`.
Allowance SHA256:
`9ddd9264c92d1b9908b6be7f7f70350e0b952852018ea3db7c084e411af3f29d`.
Policy SHA256:
`0342c19f12f4535af2f0cef4e936954ffd6f3576f547aa229ace0bd840da1d36`.

Local validation uses synthetic ledger histories, sealed mock transport and the
original private atomic plan writer. The policy is configured, but no real
reservation, provider call, bill settlement or audit has been performed. Existing
artifacts bound to the old plan are not silently rebound. Every unrelated route,
lineage, qualification, seal and release prerequisite remains in force.
