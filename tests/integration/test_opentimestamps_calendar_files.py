"""Disposable local file assembly/readback; not a live HTTP or chain integration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from mmaudit.models.opentimestamps_calendar import (
    assemble_opentimestamps_submission_proof,
    prepare_opentimestamps_calendar_request,
    prepare_opentimestamps_submission,
    replay_opentimestamps_calendar_response,
)
from mmaudit.models.opentimestamps_replay import replay_detached_opentimestamps_proof

FIXTURE = Path(__file__).parents[1] / "fixtures/opentimestamps/synthetic_calendar.json"


@pytest.mark.parametrize(
    "change",
    [
        "none",
        "document",
        "nonce",
        "reply_operation",
        "reply_suffix",
        "reply_prefix",
        "reply_truncated",
        "proof_suffix",
    ],
)
def test_local_submission_files_preserve_original_context_without_publication_credit(
    tmp_path, change
):
    fixture = json.loads(FIXTURE.read_text())
    assert fixture["synthetic_only"] is True
    document = tmp_path / "synthetic.txt"
    response = tmp_path / "calendar-response.bin"
    proof = tmp_path / "synthetic.ots"
    document.write_text(fixture["document_ascii"])
    digest = hashlib.sha256(document.read_bytes()).hexdigest()
    assert digest == fixture["file_sha256"]
    nonce = bytes.fromhex(fixture["nonce_hex"])
    request = prepare_opentimestamps_submission(file_sha256=digest, nonce=nonce)
    assert request.commitment.hex() == fixture["submission_commitment_hex"]
    # The request is only data; nothing has been submitted to a service.
    original = bytes.fromhex(fixture["raw_reply_hex"])
    if change == "document":
        document.write_text(fixture["document_ascii"] + " changed")
    elif change == "nonce":
        nonce = b"x" * 16
    elif change == "reply_operation":
        original = original.replace(b"calendar-sibling", b"Calendar-sibling")
    elif change == "reply_suffix":
        original += b"\x00"
    elif change == "reply_prefix":
        original = b"\x08" + original
    elif change == "reply_truncated":
        original = original[:-1]
    response.write_bytes(original)
    digest = hashlib.sha256(document.read_bytes()).hexdigest()
    if change in ("document", "nonce", "reply_suffix", "reply_truncated"):
        with pytest.raises(ValueError):
            assemble_opentimestamps_submission_proof(
                request,
                file_sha256=digest,
                nonce=nonce,
                status_code=200,
                body=response.read_bytes(),
            )
        assert not proof.exists()
        return
    raw = assemble_opentimestamps_submission_proof(
        request, file_sha256=digest, nonce=nonce, status_code=200, body=response.read_bytes()
    )
    proof.write_bytes(raw + (b"x" if change == "proof_suffix" else b""))
    if change == "proof_suffix":
        with pytest.raises(ValueError, match="trailing"):
            replay_detached_opentimestamps_proof(proof.read_bytes(), expected_file_sha256=digest)
        return
    result = replay_detached_opentimestamps_proof(proof.read_bytes(), expected_file_sha256=digest)
    response_result = replay_opentimestamps_calendar_response(
        request, status_code=200, body=response.read_bytes()
    )
    assert result.attestations == response_result.attestations
    assert result.entry_count == response_result.entry_count + 2
    assert result.maximum_depth == response_result.maximum_depth + 2
    assert [leaf.kind for leaf in result.attestations] == ["PENDING", "BITCOIN_HEIGHT"]
    leaf = result.attestations[1]
    assert leaf.claimed_bitcoin_height == fixture["claimed_height"]
    assert (leaf.commitment_hex == fixture["claimed_root_hex"]) is (change == "none")
    assert not hasattr(result, "require") and not hasattr(result, "release_authorized")
    # Syntactically valid altered reply operations are not authenticated by
    # request context alone. An independent trusted root must detect that change.


def test_local_pending_lookup_file_keeps_44_byte_commitment_and_no_upgrade_authority(tmp_path):
    fixture = json.loads(FIXTURE.read_text())
    body = bytes.fromhex(fixture["raw_reply_hex"])
    commitment = b"synthetic-pending-commitment-" + b"x" * 15
    assert len(commitment) == 44
    request = prepare_opentimestamps_calendar_request(operation="LOOKUP", commitment=commitment)
    response = tmp_path / "lookup-response.bin"
    response.write_bytes(body)
    result = replay_opentimestamps_calendar_response(
        request, status_code=200, body=response.read_bytes()
    )
    assert result.attestations[0].commitment_hex == commitment.hex()
    assert (
        result.attestations[1].commitment_hex
        == hashlib.sha256(b"calendar-sibling" + commitment).hexdigest()
    )
    assert not hasattr(result, "verified") and not hasattr(result, "require")
