"""Synthetic seal counterexamples, not Bitcoin or external publication verification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import fields
from pathlib import Path

import pytest

import mmaudit.orchestration.calibration_publication as publication
from mmaudit.models.evidence_seal_authority import build_transparency_prefix_proof
from mmaudit.models.opentimestamps_calendar import prepare_opentimestamps_submission
from mmaudit.models.opentimestamps_replay import replay_opentimestamps_calendar_proof
from tests.unit.test_authenticated_calibration import no_external_execution as no_external_execution
from tests.unit.test_calibration_publication import FLAGS
from tests.unit.test_calibration_publication import publication_data as publication_data

FIXTURE = (
    Path(__file__).parents[1] / "fixtures/opentimestamps/synthetic_external_seal_boundary.json"
)


def histories(data, fork):
    """Two individually consistent histories with the SAME claimed log identity."""

    results = []
    for alternate in (False, True):
        prior = "d" * 64 if alternate and fork == "before_registration" else "c" * 64
        middle = "f" * 64 if alternate and fork == "after_registration" else "e" * 64
        first = build_transparency_prefix_proof(
            log_id_sha256="a" * 64,
            authority_subject_sha256s=(prior, data.registration.subject_sha256),
        )
        last = build_transparency_prefix_proof(
            log_id_sha256="a" * 64,
            authority_subject_sha256s=(
                prior,
                data.registration.subject_sha256,
                middle,
                data.measurement.subject_sha256,
            ),
            previous_checkpoint=first.checkpoint,
        )
        results.append(
            publication.build_calibration_publication_comparison(
                registration=data.registration,
                measurement=data.measurement,
                registration_proof=first,
                measurement_proof=last,
            )
        )
    return results


def request_for_digest(digest):
    # Fixed test nonce compares preimage binding only; it is never a production nonce.
    return prepare_opentimestamps_submission(
        file_sha256=hashlib.sha256(digest).hexdigest(), nonce=b"x" * 16
    )


@pytest.mark.parametrize("fork", ["before_registration", "after_registration"])
def test_subject_stamps_do_not_select_between_conflicting_same_log_histories(
    publication_data, fork
):
    left, right = histories(publication_data, fork)
    assert left.measurement_proof.checkpoint.log_id_sha256 == (
        right.measurement_proof.checkpoint.log_id_sha256
    )
    assert left.measurement_proof.leaf_sha256s != right.measurement_proof.leaf_sha256s
    assert left.measurement_proof.checkpoint != right.measurement_proof.checkpoint
    assert left.comparison_sha256 != right.comparison_sha256
    for phase in ("registration", "measurement"):
        left_subject, right_subject = getattr(left, phase), getattr(right, phase)
        assert left_subject == right_subject
        assert request_for_digest(publication.calibration_publication_request(left_subject)) == (
            request_for_digest(publication.calibration_publication_request(right_subject))
        )

    # A checkpoint commitment would distinguish this fork. This is a local preimage
    # comparison, not an implemented publisher, authenticated origin or trust policy.
    assert request_for_digest(
        bytes.fromhex(left.measurement_proof.checkpoint.checkpoint_sha256)
    ) != request_for_digest(bytes.fromhex(right.measurement_proof.checkpoint.checkpoint_sha256))
    for value in (left, right):
        assert (
            publication.read_calibration_publication_comparison(
                publication.calibration_publication_comparison_bytes(value)
            )
            == value
        )
        assert all(
            getattr(value, flag) is (flag == "external_comparison_required") for flag in FLAGS
        )


@pytest.mark.parametrize("reverse", [False, True])
def test_crossing_the_two_forked_registration_histories_still_refuses(publication_data, reverse):
    left, right = histories(publication_data, "before_registration")
    if reverse:
        left, right = right, left
    with pytest.raises(ValueError, match="exact population/log"):
        publication.build_calibration_publication_comparison(
            registration=publication_data.registration,
            measurement=publication_data.measurement,
            registration_proof=left.registration_proof,
            measurement_proof=right.measurement_proof,
        )


def test_common_block_claim_is_not_external_phase_chronology():
    fixture = json.loads(FIXTURE.read_bytes())
    assert fixture["synthetic_only"] is True
    replies = []
    for phase in ("registration", "measurement"):
        reply = replay_opentimestamps_calendar_proof(
            bytes.fromhex(fixture[phase + "_proof_hex"]),
            expected_commitment=bytes.fromhex(fixture[phase + "_commitment_hex"]),
        )
        assert len(reply.attestations) == 1
        attestation = reply.attestations[0]
        assert attestation.kind == "BITCOIN_HEIGHT"
        assert attestation.commitment_hex == fixture["common_root_hex"]
        assert attestation.claimed_bitcoin_height == fixture["claimed_height"]
        assert {field.name for field in fields(attestation)} == {
            "kind",
            "tag_hex",
            "payload_sha256",
            "commitment_hex",
            "claimed_bitcoin_height",
        }
        replies.append(reply)
    assert replies[0].initial_commitment_hex != replies[1].initial_commitment_hex
    assert replies[0].response_sha256 != replies[1].response_sha256
    assert replies[0].attestations == replies[1].attestations
    # Equal block claims cannot place a dispatch between the two publications.
    # No header, timestamp, confirmations, accepted chain or execution is supplied.


def test_changing_the_untrusted_height_does_not_change_the_calculated_root():
    fixture = json.loads(FIXTURE.read_bytes())
    assert fixture["synthetic_only"] is True
    raw = bytes.fromhex(fixture["registration_proof_hex"])
    assert raw[-2:] == bytes((1, fixture["claimed_height"]))
    changed = raw[:-1] + bytes((fixture["alternate_unverified_height"],))
    before, after = (
        replay_opentimestamps_calendar_proof(
            proof, expected_commitment=bytes.fromhex(fixture["registration_commitment_hex"])
        )
        for proof in (raw, changed)
    )
    assert before.response_sha256 != after.response_sha256
    assert before.attestations[0].payload_sha256 != after.attestations[0].payload_sha256
    assert before.attestations[0].claimed_bitcoin_height == fixture["claimed_height"]
    assert after.attestations[0].claimed_bitcoin_height == fixture["alternate_unverified_height"]
    assert before.attestations[0].commitment_hex == after.attestations[0].commitment_hex
    assert after.attestations[0].commitment_hex == fixture["common_root_hex"]
