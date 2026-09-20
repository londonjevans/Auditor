# Synthetic coverage/debugger population control

The integration test copies `coverage_compilation` into a disposable workspace,
then copies `PopulationControl.t.sol` into its `test/` directory. The original
fixture is never modified. Both harness paths assert the same named permitted/
refused counter transition invariant; the fuzz control has eight fixed-seed cases.

This is a non-production, local-only fixture with no funds, RPC, FFI, libraries or
credentials. Compiler/coverage/debugger observations are diagnostic evidence only,
not an admitted audit, generic atomic coverage or full fuzz-trace population.
