# Frozen synthetic development corpus

Two local, intentionally non-production variants of one three-file abstract contract hierarchy.
No credentials, tokens, funds, deploy scripts, external dependencies or network endpoints are used.
`UnitRouter` retains an unimplemented mutation-record hook and is not a deployable application.

- `RoutePolicy.sol` declares administrator/gateway identity, pause controls and credit limits.
- `UnitStore.sol` implements internal unit accounting and reservations.
- `UnitRouter.sol` exposes gateway-gated operations using both dependencies.

The declared authorization invariant is that only the administrator may change the gateway trusted
by all public unit mutations. Variant `a` intentionally lacks that guard on `setGateway`; variant
`b` restores it. The other two files are byte-identical. This is a minimal negative/guarded pair,
not an incident reproduction or a claim that variant `b` is secure.

The development planner accepts only the exact compiled filename, byte-hash, size and line-count
pins for `unit-ledger-a-v1` and `unit-ledger-b-v1`. It creates one primary-file request per file in
filename order; every request includes all three files as context. Findings must anchor to the
designated primary file. This is file-level request coverage, not semantic/statement coverage or
proof that a cross-file invariant was validated. Labels and source comments reveal the intended
control: these public development inputs cannot measure held-out detection performance.

Normal tests use synthetic metadata, fake credentials, mocked HTTP and disposable local ledgers
and outputs. They do not compile, deploy, run a chain, call a model, or execute response text.

The separate `truth-a.json`/`truth-b.json` manifests freeze agent-constructed development controls
independently of scored responses. They bind the exact source pair, origin and allowed consequence
locations; they are not external/non-model-generated qualification truth or an exhaustive safety
claim. An optional `--truth-manifest` selects v2 and automatic local measurement. The planner never
sends these files or their control IDs to a model. See
[metric definitions](../../../../docs/development_benchmark.md) before interpreting a score.
