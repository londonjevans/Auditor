# mmaudit benchmark corpus

The default manifest describes original, synthetic, non-deployable Solidity fixtures under
`tests/fixtures/solidity/maximum_assurance_protocol` and executable economic controls under
`tests/fixtures/solidity/economic_erc4626`. It records expected vulnerable ranges and safe
near-miss controls without embedding proprietary audit material.

Every vulnerable class has a source-local secure counterpart in `SafeVariants.sol`; two additional
guarded near-misses in `SafeControls.sol` exercise false-positive suppression around privileged
drains and checks-effects-interactions. These controls are intentionally evaluated at high or
critical severity so a careless model-only confirmation fails the benchmark gate.

The `economic_erc4626` fixture is intentionally small enough to run with `forge test --offline`.
It contains a vulnerable donation/inflation vault and a patched virtual-share variant, giving the
benchmark suite an executable positive and negative control for ERC4626 economic testing.

`mmaudit benchmark --reports <directory>` evaluates completed audit reports. It does not pretend
that manifest parsing alone discovered a vulnerability. Results distinguish missing reports,
missed cases, safe-control false confirmations, evidence-cap bypasses, and missing coverage.
