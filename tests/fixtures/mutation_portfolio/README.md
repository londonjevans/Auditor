# Synthetic local-only mutation controls

This is intentionally non-production test material. The constructor refuses chains
other than the disposable local chain ID 31337. There are no funds, private keys,
RPC calls, imported dependencies, FFI commands or live protocol addresses.

Each named test asserts one defensive property against the safe source. The Python
integration test creates one disposable mutated copy at a time, executes all tests,
requires the corresponding property to fail, and restores exact original bytes.
This is a synthetic property control, not an audit-quality or qualification result.
