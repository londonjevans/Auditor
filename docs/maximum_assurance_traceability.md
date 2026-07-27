# Maximum-assurance traceability

`mmaudit` treats maximum assurance as a runtime contract, not a profile label.
Every audit emits `maximum_assurance_traceability.json`, conforming to
`schemas/maximum_assurance_traceability.schema.json`.

The generated matrix uses four deliberately strict states:

- `implemented`: executable implementation, an automated test, and a named runtime
  artifact all exist and pass evidence validation.
- `partially_implemented`: useful executable capability exists, but the full product
  requirement is not proven.
- `unavailable`: the required evidence or external evaluation does not exist.
- `unimplemented`: no complete executable capability exists.

Documentation, configuration, an availability probe, a mocked adapter, or a
planning-only harness cannot by itself produce `implemented`. CI must call
`validate_traceability_evidence`; an implemented row with a missing code path, test
path, or runtime artifact fails validation.

The matrix intentionally records incomplete economic harnesses, formal engines,
model qualification, OS isolation, replay, and blind professional-comparison work.
Those rows remain blocking inputs to maximum-assurance status until their executable
evidence exists.
