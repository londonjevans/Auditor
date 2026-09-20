"""Provider-free generation-proof handoff with real local structural verification.

The existing synthetic issuer deliberately has no AUTHRUNNER provider origin.
Successful moves demonstrate binding/lifetime custody, not real provider provenance.
"""

from pathlib import Path

import pytest

import mmaudit.models.generation_evidence as generation
from tests.integration.test_operator_reservation_boundary import (
    forbid_network_and_secrets as forbid_network_and_secrets,
)
from tests.unit.test_generation_evidence import (
    _STARTED,
    _evidence,
    _generation_payload,
    _resolve_trusted_generation,
    _verification_request,
)


def original_set(
    count: int,
) -> tuple[
    generation.TrustedGenerationVerification,
    tuple[generation.GenerationVerificationRequest, ...],
    tuple[generation.OpenRouterGenerationEvidence, ...],
]:
    requests = tuple(_verification_request(f"gen-move-{i}", index=i) for i in range(count))
    attestations = []
    for request in requests:
        payload = _generation_payload()
        generation_id = request.usage_record.openrouter_generation_id
        assert generation_id is not None
        payload["data"]["id"] = generation_id
        attestations.append(_evidence(payload=payload, requested_generation_id=generation_id))
    capability = generation._issue_trusted_generation_verification(
        requests=requests, attestations=tuple(attestations), verification_started_at=_STARTED
    )
    return capability, requests, tuple(attestations)


@pytest.mark.parametrize("count", (2, 512))
def test_complete_bounded_proof_moves_all_original_cases_without_network_or_native_credit(
    tmp_path: Path, forbid_network_and_secrets: list[str], count: int
) -> None:
    original, requests, attestations = original_set(count)
    before = tuple(tmp_path.iterdir())
    successor = generation.transfer_trusted_generation_verification(
        original, requests=tuple(reversed(requests))
    )
    try:
        assert not generation._has_authrunner_generation_origin(successor)
        assert tuple(_resolve_trusted_generation(successor, request) for request in requests) == (
            attestations
        )
        for request in (requests[0], requests[-1]):
            with pytest.raises(ValueError, match="not trusted"):
                _resolve_trusted_generation(original, request)
        assert tuple(tmp_path.iterdir()) == before
        assert forbid_network_and_secrets == []
    finally:
        generation.revoke_trusted_generation_verification(successor)


@pytest.mark.parametrize("kind", ("missing", "extra", "duplicate", "oversize"))
def test_handoff_cannot_trim_or_expand_the_original_proof(
    forbid_network_and_secrets: list[str], kind: str
) -> None:
    original, requests, attestations = original_set(513 if kind == "oversize" else 2)
    try:
        supplied = {
            "missing": requests[:1],
            "extra": (*requests, _verification_request("gen-extra", index=900)),
            "duplicate": (requests[0], requests[0]),
            "oversize": requests,
        }[kind]
        with pytest.raises(ValueError):
            generation.transfer_trusted_generation_verification(original, requests=supplied)
        assert _resolve_trusted_generation(original, requests[-1]) == attestations[-1]
        assert not generation._has_authrunner_generation_origin(original)
        assert forbid_network_and_secrets == []
    finally:
        generation.revoke_trusted_generation_verification(original)
