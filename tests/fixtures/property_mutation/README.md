# Synthetic generated-property mutation controls

`LocalAccounting.sol` is local-only, non-production defensive test source. Its safe
authorization and decimal-scaling behavior is challenged only in disposable mutant
copies. `tests/property_mutation_support.py` builds two exact source-backed typed
properties and uses the production deterministic local Foundry harness translator.

`snapshot.json` retains native Forge/solc 0.8.30 normalized compiler inputs from the
original inventory runner. It is a consistency fixture with explicitly MOCK isolation,
not independent compiler custody, a real protocol audit or qualification evidence.
The matching generated harness bytes are reproduced from the typed fixture inputs;
their immutable source hashes in the compiler snapshot detect translation drift.

The native integration separately recompiles and runs the source plus generated
assertions, verifies stateful calls, checks each mutant violates its corresponding
property, and verifies exact source restoration and owned-workspace disposal. No live
network, provider, wallet, RPC service or tool provisioning is used.
