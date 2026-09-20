# Retained synthetic compiler-inventory snapshot

This is the exact parser-input snapshot emitted by the native local original-runner
integration control for `tests/fixtures/mutation_portfolio`. It contains normalized
build-info and Forge test-list bytes, source hashes and explicit MOCK inventory
metadata. The source bytes are read from that existing synthetic fixture, not copied
from a deployed protocol. The compiler version and executable digest are pinned in
the snapshot; normal unit tests require no compiler or external service.

The test backend does not attest isolation. This serialized record has no live
scanner, mutation, property-applicability, qualification or release authority.
Its retained exact input hashes are consistency evidence only. Native integration
tests regenerate their own inputs using installed external tools and do not treat
this fixture as proof of a new execution.
