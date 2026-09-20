"""Local synthetic file replay only; no live chain or upstream executable is used."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from mmaudit.models.opentimestamps_replay import replay_detached_opentimestamps_proof

FIXTURE = Path(__file__).parents[1] / "fixtures/opentimestamps/synthetic_replay.json"


@pytest.mark.parametrize("change", ["none", "document", "operation", "suffix", "truncated"])
def test_local_synthetic_file_and_proof_binding_preserves_no_authority(tmp_path, change):
    fixture = json.loads(FIXTURE.read_text())
    assert fixture["synthetic_only"] is True
    document = tmp_path / "synthetic.txt"
    proof = tmp_path / "synthetic.ots"
    document.write_text(fixture["document_ascii"])
    original = bytes.fromhex(fixture["proof_hex"])
    if change == "document":
        document.write_text(fixture["document_ascii"] + " changed")
    elif change == "operation":
        original = original.replace(b"synthetic-nonce", b"Synthetic-nonce")
    elif change == "suffix":
        original += b"\x00"
    elif change == "truncated":
        original = original[:-1]
    proof.write_bytes(original)
    expected = hashlib.sha256(document.read_bytes()).hexdigest()
    if change in ("document", "suffix", "truncated"):
        with pytest.raises(ValueError):
            replay_detached_opentimestamps_proof(proof.read_bytes(), expected_file_sha256=expected)
        return
    observed = replay_detached_opentimestamps_proof(
        proof.read_bytes(), expected_file_sha256=expected
    )
    assert observed.file_sha256 == fixture["file_sha256"]
    assert observed.entry_count == 5 and observed.maximum_depth == 5
    assert len(observed.attestations) == 1
    leaf = observed.attestations[0]
    assert leaf.claimed_bitcoin_height == fixture["claimed_height"]
    assert (leaf.commitment_hex == fixture["root_hex"]) is (change == "none")
    # A changed operation is still syntactically valid; only an authenticated
    # external root could reject its new commitment as an invalid publication.
    assert not hasattr(observed, "require")
    assert not hasattr(observed, "release_authorized")
