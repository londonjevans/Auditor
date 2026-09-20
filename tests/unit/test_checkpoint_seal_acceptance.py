"""Synthetic acceptance counterexamples; never external chain or release evidence."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from types import SimpleNamespace

import httpx
import pytest

import mmaudit.models.calibration_checkpoint as checkpoint
from mmaudit.models.evidence_seal_authority import build_transparency_prefix_proof
from mmaudit.models.opentimestamps_calendar import prepare_opentimestamps_submission
from mmaudit.models.opentimestamps_replay import replay_opentimestamps_calendar_proof
from mmaudit.orchestration.calibration_checkpoint_publication import (
    load_calibration_checkpoint_publication,
)
from tests.unit.test_authenticated_calibration import no_external_execution as no_external_execution
from tests.unit.test_calibration_calendar_controller import assert_disposed, execute
from tests.unit.test_calibration_calendar_controller import controller_state as controller_state
from tests.unit.test_calibration_checkpoint import pair
from tests.unit.test_calibration_population_journal import read_journal
from tests.unit.test_calibration_publication import FLAGS
from tests.unit.test_calibration_publication import publication_data as publication_data
from tests.unit.test_opentimestamps_calendar import attestation, blob
from tests.unit.test_opentimestamps_calendar_transport import Stream
from tests.unit.test_opentimestamps_calendar_transport import install_client as install_client
from tests.unit.test_registered_calibration_measurement import (
    measurement_protocol as measurement_protocol,
)


def competing_checkpoints(data, fork):
    """Construct two ordinary data views, not two accepted log histories."""

    seed = build_transparency_prefix_proof(
        log_id_sha256="a" * 64, authority_subject_sha256s=("c" * 64,)
    )
    views = []
    for branch in ("d" * 64, "e" * 64):
        prefix = ("c" * 64, branch) if fork == "before_registration" else ("c" * 64,)
        first_subjects = (*prefix, data.registration.subject_sha256)
        first = build_transparency_prefix_proof(
            log_id_sha256="a" * 64,
            authority_subject_sha256s=first_subjects,
            previous_checkpoint=seed.checkpoint,
        )
        extra = (branch,) if fork == "after_registration" else ()
        last = build_transparency_prefix_proof(
            log_id_sha256="a" * 64,
            authority_subject_sha256s=(*first_subjects, *extra, data.measurement.subject_sha256),
            previous_checkpoint=first.checkpoint,
        )
        views.append(
            pair(
                SimpleNamespace(
                    registration=data.registration,
                    measurement=data.measurement,
                    registration_proof=first,
                    measurement_proof=last,
                )
            )
        )
    return seed, views


@pytest.mark.parametrize("fork", ["before_registration", "after_registration"])
def test_competing_checkpoint_views_can_share_an_anchor_without_selecting_a_log_history(
    publication_data, fork
):
    seed, ((left_first, left), (right_first, right)) = competing_checkpoints(publication_data, fork)
    assert left_first.transparency_proof.previous_checkpoint == seed.checkpoint
    assert right_first.transparency_proof.previous_checkpoint == seed.checkpoint
    assert left.population_subject_sha256 == right.population_subject_sha256
    assert left.transparency_proof.checkpoint.log_id_sha256 == (
        right.transparency_proof.checkpoint.log_id_sha256
    )
    assert left.transparency_proof.leaf_sha256s != right.transparency_proof.leaf_sha256s
    assert left.subject_sha256 != right.subject_sha256  # The implemented binding distinguishes it.
    requests = tuple(
        prepare_opentimestamps_submission(
            file_sha256=hashlib.sha256(
                checkpoint.calibration_checkpoint_publication_request(value)
            ).hexdigest(),
            nonce=b"x" * 16,  # Fixed test nonce, never a production source.
        )
        for value in (left, right)
    )
    left_commitment, right_commitment = (request.commitment for request in requests)
    assert left_commitment != right_commitment
    expected_root = hashlib.sha256(left_commitment + right_commitment).hexdigest()
    # Two independently assembled synthetic paths to one aggregate commitment.
    # No header, accepted chain, timestamp, confirmation or external contact is supplied.
    proofs = (
        b"\xf0" + blob(right_commitment) + b"\x08" + attestation(payload=b"\x11"),
        b"\xf1" + blob(left_commitment) + b"\x08" + attestation(payload=b"\x11"),
    )
    observations = tuple(
        replay_opentimestamps_calendar_proof(raw, expected_commitment=request.commitment)
        for raw, request in zip(proofs, requests, strict=True)
    )
    assert observations[0].response_sha256 != observations[1].response_sha256
    assert observations[0].attestations == observations[1].attestations
    assert observations[0].attestations[0].commitment_hex == expected_root
    assert observations[0].attestations[0].claimed_bitcoin_height == 17
    # Inclusion can bind both competing views. It does not elect one accepted successor.
    for value in (left_first, left, right_first, right):
        assert all(
            getattr(value, flag) is (flag == "external_comparison_required") for flag in FLAGS
        )


@pytest.mark.parametrize("fork", ["before_registration", "after_registration"])
def test_exact_checkpoint_pin_still_refuses_the_other_internally_valid_view(publication_data, fork):
    _, ((first, left), (_, right)) = competing_checkpoints(publication_data, fork)
    with pytest.raises(ValueError, match="original checkpoint or population"):
        checkpoint.build_calibration_checkpoint_subject(
            subject=publication_data.measurement,
            transparency_proof=left.transparency_proof,
            expected_checkpoint_sha256=right.transparency_proof.checkpoint.checkpoint_sha256,
            registration=first,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("late_liability", [False, True])
async def test_recorded_measurement_cannot_replace_native_terminal_custody(
    controller_state, install_client, late_liability
):
    state = controller_state(checkpoint=True)
    recorded = []
    readbacks = []

    def reply(_):
        if state.events[-1] == "measurement":
            state.require(state.proof, state.measured)
            assert read_journal(state.root)[-1].kind == "RUNNER_RETAINED"
            assert not (state.output / "measurement.json").exists()
            recorded.append((state.measurement_output / "checkpoint.json").read_bytes())
        return httpx.Response(200, stream=Stream([attestation()]))

    def readback():
        assert not state.runner_live
        with pytest.raises(ValueError, match="absent or revoked"):
            state.require(state.proof, state.measured)
        terminal = read_journal(state.root)[-1]
        assert terminal.kind == "FINISHED" and terminal.disposition == "CONSUMED"
        assert (state.output / "measurement.json").is_file()
        assert (state.measurement_output / "checkpoint.json").read_bytes() == recorded[0]
        readbacks.append(terminal)
        if late_liability:
            charge = state.ledger.reserve("synthetic-post-checkpoint-liability", Decimal("1"))
            state.ledger.reconcile(charge, None)

    state.on_readback = readback
    clients, _, requests = install_client(reply)
    if late_liability:
        with pytest.raises(ValueError):
            await execute(state)
    else:
        result = await execute(state)
        assert result.measurement.receipt.completed_event_sha256 == readbacks[0].event_sha256
        assert result.measurement.receipt.release_authorized is False
    assert len(readbacks) == len(recorded) == 1
    descriptor = json.loads((state.measurement_output / "publication.json").read_bytes())
    phase = load_calibration_checkpoint_publication(
        output_root=state.measurement_output,
        expected_publication_sha256=descriptor["publication_sha256"],
    )
    assert (state.measurement_output / "checkpoint.json").read_bytes() == recorded[0]
    assert phase.subject.population_events[-1].kind == "RUNNER_RETAINED"
    assert all(event.kind != "FINISHED" for event in phase.subject.population_events)
    assert phase.calendar.events[-1].kind == "POST_REPLAYED"
    assert phase.binding.release_authorized is phase.binding.external_publication_verified is False
    # Each original phase remains byte-identical across clean completion or a refused liability.
    # Reopened data still cannot recreate the disposed native proof or authorize release.
    with pytest.raises(ValueError, match="absent or revoked"):
        state.require(state.proof, state.measured)
    assert len(requests) == 2 and all(client.is_closed for client in clients)
    assert_disposed(state)
