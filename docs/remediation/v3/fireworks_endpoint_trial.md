# Fireworks candidate endpoint trial — V3-ENDPOINTTRIAL-001

Jos's September-11 direct instruction authorizes this endpoint trial only. It does not
authorize a candidate-model, judge-route, request-requirement or other policy change.
The implementation is local staging, not evidence that Fireworks satisfies the predicates.

The already-staged private plan is:
`.mmaudit/operator-shared/discovery/deepseek-fireworks-selection-plan-v1.12.json`.
It is a canonical 0600 file, 19519 bytes, ignored by Git and not the active repository plan.

- Staged raw SHA256: `13b4f19ab3dade307e9eb709d3ca1e72fb57f3d2ba6bb373e823d32d297dba9e`.
- Staged plan SHA256: `623d5ca632eaeb7e51c5cada20e00712d06d50105e86173f90d93c4a80ae431c`.
- Exact v1.11 predecessor raw SHA256: `7af8d0eeeade437767c965482c563dafa893ce76eee818333fd728daab7cdbb0`.

The new `OP-ENDPOINTTRIAL-2026-09-11` binding separately identifies the trial. Authenticated
ancestry reconstructs the complete original v1.11 before adding Fireworks; it does not
rewrite the earlier cost transition. The original Together constraint stays on record.
The new endpoint is selected explicitly for this trial, never through automatic fallback.

| Role | Exact model | Trial endpoint |
|---|---|---|
| Candidate | `deepseek/deepseek-v4-pro-0813` | `fireworks` |
| Primary judge | `z-ai/glm-5.2` | `deepinfra/fp4` |
| Replay judge | `moonshotai/kimi-k3` | `together` |

The original judge constraints are byte-identical. `required_output_mode=NATIVE_JSON_SCHEMA`,
`required_reasoning_effort=high`, `required_supported_parameters=[structured_outputs]`,
completion limits, ZDR, singleton routing, reservation policy and the exact legacy allowance
are unchanged. Neither historical uncertain ledger row is rewritten or settled.
The active `config/models.selection-plan.json` remains v1.11. The current active-plan
validator deliberately refuses v1.12 adoption. All qualification, lineage, evidence-seal,
release and durable-run prerequisites remain in force.

## Monitoring-session handoff

Only the monitoring session may run **one** `authenticated-runner-smoke` for Fireworks under
the direct instruction. Codex has made no provider call and has not inspected the private ledger.
Use singleton discovery and registry evidence bound to this staged plan; do not silently rebind
old v1.11 registries or reuse a different endpoint's evidence. The existing native-output,
reasoning, supported-parameter, source, lineage and cost checks must all pass normally.

The smoke command must include all three tripwires, without changing any other requirement:

```text
--candidate-cost-cap-usd-per-attempt 0.30
--primary-judge-cost-cap-usd-per-attempt 0.30
--replay-judge-cost-cap-usd-per-attempt 0.30
```

Use the monitoring session's existing authorized inputs and cumulative ledger, and a fresh
smoke index/output. No actual paths, index or capability are inferred here. Do not run the
durable `authenticated-runner`, adopt a plan, qualify a model or publish an evidence seal.
An estimate above a tripwire must refuse; a new uncertain bill, reservation overrun or exhausted
ceiling still blocks further work. The old two-row allowance does not cover any new failure.

Record the exact endpoint, predecessor/staged hashes, result, refusal predicate, attempt count
and actual/uncertain costs in `operator_results.md`. If Fireworks fails the same way as the
preceding Together attempt, the conditional order is `sail-research/fp4`, then `phala`, one
endpoint at a time. Neither later endpoint is staged or enabled by this implementation; a
reported preceding result is required before the next bounded amendment. Different failures,
including unknown billing, do not justify bypassing another gate or automatically advancing.

## Provider-free reproduction

The original plan emitter supports the narrow `--candidate-endpoint-trial` switch. To produce
another private copy, use a fresh output path in an existing 0700 directory; do not rerun it
against the already-staged file or the active plan:

```text
.venv/bin/python -m mmaudit models emit-selection-plan-reactivation \
  --candidate deepseek/deepseek-v4-pro-0813=fireworks \
  --candidate-endpoint-trial \
  --output /absolute/private/fresh-fireworks-trial.json
```

This command derives and writes a nonauthorizing plan only. It does not contact providers,
load operator credentials, edit a ledger, adopt a plan or create an evidence seal. Mixed
endpoint/cost-transition modes and Sail Research/Phala selections currently refuse.
