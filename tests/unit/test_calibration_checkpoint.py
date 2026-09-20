"""Checkpoint preimage binding tests using isolated synthetic population evidence."""

from __future__ import annotations

import hashlib
import json

import pytest

import mmaudit.models.calibration_checkpoint as checkpoint
import mmaudit.orchestration.calibration_publication as publication
from mmaudit.models.opentimestamps_calendar import prepare_opentimestamps_submission
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from tests.unit.test_authenticated_calibration import no_external_execution as no_external_execution
from tests.unit.test_calibration_external_seal_boundary import histories
from tests.unit.test_calibration_publication import FLAGS
from tests.unit.test_calibration_publication import publication_data as publication_data


def pair(data):
    first = checkpoint.build_calibration_checkpoint_subject(
        subject=data.registration,
        transparency_proof=data.registration_proof,
        expected_checkpoint_sha256=data.registration_proof.checkpoint.checkpoint_sha256,
    )
    last = checkpoint.build_calibration_checkpoint_subject(
        subject=data.measurement,
        transparency_proof=data.measurement_proof,
        expected_checkpoint_sha256=data.measurement_proof.checkpoint.checkpoint_sha256,
        registration=first,
    )
    return first, last


def reseal(data):
    data = dict(data)
    data.pop("subject_sha256", None)
    return stable_json({**data, "subject_sha256": canonical_sha256(data)}).encode()


@pytest.mark.parametrize("fork", ["before_registration", "after_registration"])
def test_checkpoint_requests_distinguish_the_existing_same_subject_forks(publication_data, fork):
    left, right = histories(publication_data, fork)
    left_first, left_last = pair(left)
    right_first, right_last = pair(right)
    assert left.measurement == right.measurement
    assert left_last.transparency_proof.checkpoint != right_last.transparency_proof.checkpoint
    assert checkpoint.calibration_checkpoint_publication_request(left_last) != (
        checkpoint.calibration_checkpoint_publication_request(right_last)
    )
    # Same owned-digest convention and fixed TEST nonce must still distinguish histories.
    requests = tuple(
        prepare_opentimestamps_submission(
            file_sha256=hashlib.sha256(
                checkpoint.calibration_checkpoint_publication_request(value)
            ).hexdigest(),
            nonce=b"x" * 16,
        )
        for value in (left_last, right_last)
    )
    assert requests[0].body != requests[1].body
    assert left_first.population_subject_sha256 == right_first.population_subject_sha256
    assert (left_first.subject_sha256 == right_first.subject_sha256) is (
        fork == "after_registration"
    )


def test_both_phases_roundtrip_as_new_domain_data_without_authority(publication_data):
    first, last = pair(publication_data)
    assert last.registration_checkpoint_subject_sha256 == first.subject_sha256
    assert last.registration_event_sha256 == first.registration_event_sha256
    assert last.transparency_proof.previous_checkpoint == first.transparency_proof.checkpoint
    for value, original in zip(
        (first, last), (publication_data.registration, publication_data.measurement), strict=True
    ):
        raw = checkpoint.calibration_checkpoint_subject_bytes(value)
        assert checkpoint.read_calibration_checkpoint_subject(raw) == value
        assert value.population_subject_sha256 == original.subject_sha256
        assert value.subject_sha256 != original.subject_sha256
        assert value.artifact_kind == "CALIBRATION_CHECKPOINT_SUBJECT"
        assert value.publication_profile == "CALIBRATION_TRANSPARENCY_CHECKPOINT_V1"
        assert all(
            getattr(value, flag) is (flag == "external_comparison_required") for flag in FLAGS
        )
        with pytest.raises(ValueError):
            publication.read_calibration_publication_subject(raw)
        with pytest.raises(ValueError, match="exact subject type"):
            publication.calibration_publication_request(value)
        with pytest.raises(ValueError):
            checkpoint.read_calibration_checkpoint_subject(
                publication.calibration_publication_subject_bytes(original)
            )


@pytest.mark.parametrize("field", FLAGS)
@pytest.mark.parametrize("bad", [1, "false", None])
def test_checkpoint_flags_cannot_coerce_or_grant_authority(publication_data, field, bad):
    first, _ = pair(publication_data)
    data = first.model_dump(mode="json")
    data[field] = bad
    with pytest.raises(ValueError):
        checkpoint.read_calibration_checkpoint_subject(reseal(data))


@pytest.mark.parametrize("change", ["whitespace", "extra", "hash", "phase", "kind", "profile"])
def test_checkpoint_reader_refuses_incoherent_or_noncanonical_data(publication_data, change):
    first, _ = pair(publication_data)
    data = first.model_dump(mode="json")
    if change == "whitespace":
        raw = json.dumps(data).encode()
    elif change == "extra":
        data["unexpected"] = False
        raw = reseal(data)
    elif change == "hash":
        data["subject_sha256"] = "0" * 64
        raw = stable_json(data).encode()
    else:
        field, value = {
            "phase": ("phase", "MEASURED_POPULATION"),
            "kind": ("artifact_kind", "CALIBRATION_PUBLICATION_SUBJECT"),
            "profile": ("publication_profile", "CALIBRATION_TRANSPARENCY_CHECKPOINT_V2"),
        }[change]
        data[field] = value
        raw = reseal(data)
    with pytest.raises(ValueError):
        checkpoint.read_calibration_checkpoint_subject(raw)


@pytest.mark.parametrize("bad", [None, {}, object()])
def test_measurement_requires_original_typed_registration(publication_data, bad):
    with pytest.raises(ValueError, match="original registration"):
        checkpoint.build_calibration_checkpoint_subject(
            subject=publication_data.measurement,
            transparency_proof=publication_data.measurement_proof,
            expected_checkpoint_sha256=publication_data.measurement_proof.checkpoint.checkpoint_sha256,
            registration=bad,
        )


@pytest.mark.parametrize("change", ["checkpoint", "subject", "registration", "fork"])
def test_checkpoint_inputs_cannot_be_swapped_or_coherently_resealed(publication_data, change):
    first, _ = pair(publication_data)
    subject, proof, pin, prior = (
        publication_data.measurement,
        publication_data.measurement_proof,
        publication_data.measurement_proof.checkpoint.checkpoint_sha256,
        first,
    )
    if change == "checkpoint":
        pin = "f" * 64
    elif change == "subject":
        proof = publication_data.registration_proof
        pin = proof.checkpoint.checkpoint_sha256
    elif change == "registration":
        data = first.model_dump(mode="json")
        data["registration_event_sha256"] = "f" * 64
        prior = checkpoint.read_calibration_checkpoint_subject(reseal(data))
    else:
        _, other = histories(publication_data, "before_registration")
        prior, _ = pair(other)
    with pytest.raises(ValueError):
        checkpoint.build_calibration_checkpoint_subject(
            subject=subject,
            transparency_proof=proof,
            expected_checkpoint_sha256=pin,
            registration=prior,
        )


def test_original_registration_cannot_be_a_later_phase(publication_data):
    first, last = pair(publication_data)
    for prior in (first, last):
        with pytest.raises(ValueError, match="cannot name"):
            checkpoint.build_calibration_checkpoint_subject(
                subject=publication_data.registration,
                transparency_proof=publication_data.registration_proof,
                expected_checkpoint_sha256=publication_data.registration_proof.checkpoint.checkpoint_sha256,
                registration=prior,
            )
    with pytest.raises(ValueError, match="extend"):
        checkpoint.build_calibration_checkpoint_subject(
            subject=publication_data.measurement,
            transparency_proof=publication_data.measurement_proof,
            expected_checkpoint_sha256=publication_data.measurement_proof.checkpoint.checkpoint_sha256,
            registration=last,
        )


@pytest.mark.parametrize("bad", ["", "f" * 63, "A" * 64, 1, None])
def test_checkpoint_pin_must_be_exact(publication_data, bad):
    with pytest.raises(ValueError, match="original checkpoint pin"):
        checkpoint.build_calibration_checkpoint_subject(
            subject=publication_data.registration,
            transparency_proof=publication_data.registration_proof,
            expected_checkpoint_sha256=bad,
        )


def test_checkpoint_bytes_and_original_nested_proof_remain_bounded(publication_data, monkeypatch):
    first, _ = pair(publication_data)
    raw = checkpoint.calibration_checkpoint_subject_bytes(first)
    monkeypatch.setattr(checkpoint, "MAX_CALIBRATION_CHECKPOINT_SUBJECT_BYTES", len(raw))
    assert checkpoint.read_calibration_checkpoint_subject(raw) == first
    monkeypatch.setattr(checkpoint, "MAX_CALIBRATION_CHECKPOINT_SUBJECT_BYTES", len(raw) - 1)
    with pytest.raises(ValueError, match="over bound"):
        checkpoint.calibration_checkpoint_subject_bytes(first)
    monkeypatch.setattr(checkpoint, "MAX_CALIBRATION_CHECKPOINT_SUBJECT_BYTES", 1)
    with pytest.raises(ValueError, match="proof exceeds"):
        checkpoint.build_calibration_checkpoint_subject(
            subject=publication_data.registration,
            transparency_proof=publication_data.registration_proof,
            expected_checkpoint_sha256=publication_data.registration_proof.checkpoint.checkpoint_sha256,
        )
