# Synthetic offline RPC read control

This intentionally incomplete, non-production fixture contains no live chain state,
credentials, funds or executable contract. It supplies three deterministic read results
to test pinned archive ingestion, missing-read refusal and in-process replay. It is not
an EVM snapshot, benchmark ground truth, chain attestation or qualification evidence.
Every unrecorded account, slot or method must remain unavailable, never assumed zero.
