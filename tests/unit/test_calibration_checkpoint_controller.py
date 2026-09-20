"""Actual local batch integration with isolated native stand-ins, not external seals."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest

import mmaudit.models.calibration_checkpoint as checkpoint
import mmaudit.orchestration.calibration_calendar_controller as controller
from mmaudit.models.evidence_seal_authority import build_transparency_prefix_proof
from mmaudit.orchestration.calibration_calendar_publication import (
    CalibrationCalendarPublicationCancelled,
)
from tests.unit.test_calibration_calendar_controller import assert_disposed, execute
from tests.unit.test_calibration_calendar_controller import controller_state as controller_state
from tests.unit.test_calibration_population_journal import read_journal
from tests.unit.test_calibration_publication import FLAGS
from tests.unit.test_opentimestamps_calendar import PENDING, attestation, blob
from tests.unit.test_opentimestamps_calendar_transport import Stream
from tests.unit.test_opentimestamps_calendar_transport import install_client as install_client
from tests.unit.test_registered_calibration_measurement import (
    measurement_protocol as measurement_protocol,
)


def initial_tip(subjects=("b" * 64, "c" * 64)):
    return build_transparency_prefix_proof(
        log_id_sha256="a" * 64, authority_subject_sha256s=subjects
    )


def set_tip(state, tip=None):
    if tip is None:
        tip = initial_tip()
    state.args.update(
        initial_transparency_proof=tip,
        expected_initial_checkpoint_sha256=tip.checkpoint.checkpoint_sha256,
    )
    return tip


@pytest.mark.parametrize("prior_count", [0, 1, 3])
def test_extension_matches_original_full_subject_builder_without_rehashing_leaves(prior_count):
    subjects = tuple(f"{index:064x}" for index in range(prior_count))
    prior = initial_tip(subjects) if subjects else None
    observed = checkpoint.extend_calibration_checkpoint_proof(
        population_subject_sha256="d" * 64, log_id_sha256="a" * 64, previous=prior
    )
    expected = build_transparency_prefix_proof(
        log_id_sha256="a" * 64,
        authority_subject_sha256s=(*subjects, "d" * 64),
        previous_checkpoint=prior.checkpoint if prior is not None else None,
    )
    assert observed == expected
    assert observed.subject_leaf_index == prior_count


@pytest.mark.parametrize("bad", ["duplicate", "log", "subject", "untyped"])
def test_extension_rejects_duplicate_wrong_log_and_malformed_inputs(bad):
    prior = initial_tip()
    args = dict(population_subject_sha256="d" * 64, log_id_sha256="a" * 64, previous=prior)
    if bad == "duplicate":
        args["population_subject_sha256"] = "b" * 64
    elif bad == "log":
        args["log_id_sha256"] = "e" * 64
    elif bad == "subject":
        args["population_subject_sha256"] = "D" * 64
    else:
        args["previous"] = prior.model_dump(mode="json")
    with pytest.raises(ValueError):
        checkpoint.extend_calibration_checkpoint_proof(**args)


def test_extension_keeps_the_original_ten_thousand_leaf_boundary():
    subjects = tuple(f"{index:064x}" for index in range(9_999))
    prior = initial_tip(subjects)
    final = checkpoint.extend_calibration_checkpoint_proof(
        population_subject_sha256="d" * 64, log_id_sha256="a" * 64, previous=prior
    )
    assert final.checkpoint.tree_size == checkpoint.MAX_CALIBRATION_CHECKPOINT_LOG_LEAVES == 10_000
    with pytest.raises(ValueError, match="bounded original prefix"):
        checkpoint.extend_calibration_checkpoint_proof(
            population_subject_sha256="e" * 64, log_id_sha256="a" * 64, previous=final
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("count,seeded", [(1, False), (1, True), (8, True)])
async def test_actual_batch_records_exact_checkpoint_extensions_before_preflight_and_disposal(
    controller_state, install_client, count, seeded
):
    state = controller_state(count, checkpoint=True)
    tip = set_tip(state) if seeded else None
    proof_bytes = None if tip is None else checkpoint._proof_bytes(tip)
    observed_profiles = []

    def reply(request):
        registration = state.events[-1] == "registration"
        root = state.registration_output if registration else state.measurement_output
        descriptor = json.loads((root / "publication.json").read_bytes())
        envelope = checkpoint.read_calibration_checkpoint_subject(
            (root / "checkpoint.json").read_bytes()
        )
        assert descriptor["artifact_kind"] == "CALIBRATION_CHECKPOINT_CALENDAR_PUBLICATION"
        assert descriptor["preparation"]["subject_sha256"] == envelope.subject_sha256
        assert descriptor["preparation"]["commitment_hex"] == request.content.hex()
        assert envelope.population_subject_sha256 != envelope.subject_sha256
        assert {p.name for p in (root / "source/calendar").iterdir()} == {"000.json"}
        assert (root / "calendar/001.json").is_file()
        population = read_journal(state.root)
        if registration:
            assert len(population) == 1 and population[0].kind == "REGISTERED"
            assert not any(e.startswith("preflight") for e in state.events)
        else:
            assert population[-1].kind == "RUNNER_RETAINED"
            assert all(slot.state == "RETAINED" for slot in population[-1].slots)
            state.require(state.proof, state.measured)
        observed_profiles.append(envelope)
        return httpx.Response(200, stream=Stream([attestation()]))

    clients, _, requests = install_client(reply)
    result = await execute(state)
    assert type(result) is controller.CheckpointRecordedCalibrationResult
    first, last = result.registration.checkpoint, result.measurement_publication.checkpoint
    assert observed_profiles == [first, last]
    assert first.transparency_proof.previous_checkpoint == (None if tip is None else tip.checkpoint)
    assert last.transparency_proof.previous_checkpoint == first.transparency_proof.checkpoint
    assert last.transparency_proof.leaf_sha256s[:-1] == first.transparency_proof.leaf_sha256s
    assert last.registration_checkpoint_subject_sha256 == first.subject_sha256
    assert (
        result.measurement_publication.binding.registration_publication_sha256
        == result.registration.binding.publication_sha256
    )
    assert result.measurement.calibration.selected_model_ids == tuple(
        entry.exact_model_id for entry in state.plan.entries
    )
    assert result.measurement_publication.subject.calibration == result.measurement.calibration
    assert result.measurement_publication.subject.policy == result.measurement.policy
    assert (result.measurement.policy is not None) is (count == 8)
    assert state.events[: count + 1] == ["registration", *(f"preflight-{i}" for i in range(count))]
    assert read_journal(state.root)[-1].disposition == "CONSUMED"
    assert len(requests) == 2 and all(client.is_closed for client in clients)
    assert proof_bytes == (None if tip is None else checkpoint._proof_bytes(tip))
    assert all(
        getattr(value, flag) is (flag == "external_comparison_required")
        for value in (
            first,
            last,
            result.registration.binding,
            result.measurement_publication.binding,
        )
        for flag in FLAGS
    )
    assert not hasattr(result, "verification")
    assert_disposed(state)


@pytest.mark.asyncio
async def test_legacy_entry_point_keeps_population_only_files_and_exact_result_type(
    controller_state, install_client
):
    state = controller_state()
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    result = await execute(state)
    assert type(result) is controller.CalendarRecordedCalibrationResult
    for root in (state.registration_output, state.measurement_output):
        assert (root / "subject.json").is_file() and not (root / "checkpoint.json").exists()
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid",
    [
        "missing_pin",
        "wrong_pin",
        "wrong_log",
        "untyped",
        "fresh_with_pin",
        "noncanonical_pin",
        "invalid_log",
    ],
)
async def test_initial_tip_must_be_exact_before_registration_and_clears_secrets(
    controller_state, install_client, invalid
):
    state = controller_state(checkpoint=True)
    tip = set_tip(state)
    changes = {
        "missing_pin": {"expected_initial_checkpoint_sha256": None},
        "wrong_pin": {"expected_initial_checkpoint_sha256": "e" * 64},
        "wrong_log": {"transparency_log_id_sha256": "e" * 64},
        "untyped": {"initial_transparency_proof": tip.model_dump(mode="json")},
        "fresh_with_pin": {"initial_transparency_proof": None},
        "noncanonical_pin": {"expected_initial_checkpoint_sha256": "A" * 64},
        "invalid_log": {"transparency_log_id_sha256": None},
    }[invalid]
    _, _, requests = install_client(lambda _: pytest.fail("invalid initial tip dispatched"))
    with pytest.raises(ValueError):
        await execute(state, **changes)
    assert not requests and not state.events and not state.registration_output.exists()
    assert not tuple(state.root.iterdir()) and not tuple(state.output.iterdir())
    assert_disposed(state)


@pytest.mark.asyncio
async def test_both_phase_leaf_slots_are_reserved_before_any_registration(
    controller_state, install_client
):
    state = controller_state(checkpoint=True)
    set_tip(state, initial_tip(tuple(f"{index:064x}" for index in range(9_999))))
    _, _, requests = install_client(lambda _: pytest.fail("insufficient log capacity dispatched"))
    with pytest.raises(ValueError, match="two phase slots"):
        await execute(state)
    assert not requests and not state.events and not state.registration_output.exists()
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stage", ["registration", "preflight", "measurement", "cleanup", "readback"]
)
async def test_original_initial_tip_cannot_be_coherently_changed_during_the_batch(
    controller_state, install_client, stage
):
    state = controller_state(checkpoint=True)
    tip = set_tip(state)
    reached = []

    def mutate(*_):
        alternate = initial_tip(("e" * 64, "f" * 64))
        for field in type(tip).model_fields:
            object.__setattr__(tip, field, getattr(alternate, field))
        reached.append(stage)

    if stage != "registration":
        setattr(state, "on_" + stage, mutate)

    def reply(_):
        return httpx.Response(
            200,
            stream=Stream([attestation()], on_chunk=mutate if stage == "registration" else None),
        )

    _, _, requests = install_client(reply)
    with pytest.raises(ValueError, match="initial tip"):
        await execute(state)
    assert reached == [stage]
    if stage in {"registration", "preflight"}:
        assert not any(event.startswith("runner") for event in state.events)
    assert len(requests) == (2 if stage in {"cleanup", "readback"} else 1)
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["registration", "measurement"])
@pytest.mark.parametrize("outcome", ["http_error", "invalid", "cancel"])
async def test_checkpoint_exchange_failure_never_retries_or_completes_the_batch(
    controller_state, install_client, phase, outcome
):
    state = controller_state(checkpoint=True)

    def reply(_):
        if state.events[-1] == phase:
            if outcome == "cancel":
                raise asyncio.CancelledError
            return httpx.Response(
                503 if outcome == "http_error" else 200, stream=Stream([b"invalid"])
            )
        return httpx.Response(200, stream=Stream([attestation()]))

    clients, _, requests = install_client(reply)
    with pytest.raises(asyncio.CancelledError if outcome == "cancel" else ValueError):
        await execute(state)
    assert len(requests) == (1 if phase == "registration" else 2)
    assert all(client.is_closed for client in clients)
    assert not (state.output / "measurement.json").exists()
    assert read_journal(state.root)[-1].disposition == (
        "CANCELLED" if outcome == "cancel" else "FAILED"
    )
    if phase == "registration":
        assert not any(event.startswith(("preflight", "runner")) for event in state.events)
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["preflight", "runner", "cleanup"])
async def test_checkpoint_recording_preserves_original_failures_and_unknown_costs(
    controller_state, install_client, failure
):
    state = controller_state(3, checkpoint=True)
    setattr(state, "fail_" + failure, 1)
    _, _, requests = install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError):
        await execute(state)
    final = read_journal(state.root)[-1]
    assert final.disposition == "FAILED" and len(final.slots) == 3
    assert len(requests) == (2 if failure == "cleanup" else 1)
    if failure == "runner":
        assert state.ledger.snapshot().entries[-1].actual_cost_usd is None
        assert "runner-2" not in state.events
    assert not (state.output / "measurement.json").exists()
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "module,name",
    [
        ("checkpoint_publisher_module", "prepare_calibration_registration_checkpoint"),
        ("checkpoint_publisher_module", "prepare_calibration_measurement_checkpoint"),
        ("checkpoint_publisher_module", "load_calibration_checkpoint_publication"),
        ("checkpoint_module", "extend_calibration_checkpoint_proof"),
        ("population_module", "build_calibration_registration_publication"),
        ("population_module", "build_calibration_measurement_publication"),
    ],
)
async def test_checkpoint_producer_is_original_not_an_injected_callback(
    controller_state, module, name
):
    state = controller_state(checkpoint=True)
    setattr(getattr(state, module), name, lambda **_: pytest.fail("replacement invoked"))
    with pytest.raises(ValueError, match="original producers"):
        await execute(state)
    assert not state.events and not state.registration_output.exists()
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("original", ["native", "preflight"])
async def test_original_production_admission_still_refuses_checkpoint_protocol_standins(
    controller_state, install_client, original
):
    state = controller_state(
        checkpoint=True,
        original_native=original == "native",
        original_preflight=original == "preflight",
    )
    _, _, requests = install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError):
        await execute(state)
    assert len(requests) == 1 and not state.measurement_output.exists()
    assert not (state.output / "measurement.json").exists()
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["pending", "opaque"])
async def test_checkpoint_profile_does_not_promote_calendar_claims_to_seals(
    controller_state, install_client, kind
):
    state = controller_state(checkpoint=True)
    body = (
        attestation(PENDING, blob(b"https://untrusted-pending.invalid"))
        if kind == "pending"
        else attestation(b"opaque!!", b"synthetic")
    )
    _, _, requests = install_client(lambda _: httpx.Response(200, stream=Stream([body])))
    result = await execute(state)
    assert [r.method for r in requests] == ["POST", "POST"]
    assert all(r.url.host == "calendar.invalid" for r in requests)
    for phase in (result.registration, result.measurement_publication):
        assert phase.binding.external_publication_verified is False
        assert phase.binding.pre_dispatch_anchoring_verified is False
        assert phase.checkpoint.model_qualification_authorized is False
    assert result.measurement.receipt.release_authorized is False
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("permission", [False, 1, "true"])
async def test_checkpoint_contact_permission_is_not_implied_by_a_valid_tip(
    controller_state, install_client, permission
):
    state = controller_state(checkpoint=True)
    set_tip(state)
    _, _, requests = install_client(lambda _: pytest.fail("unapproved checkpoint contact"))
    with pytest.raises(ValueError, match="authorization"):
        await execute(state, allow_calendar_contact=permission)
    assert not requests and not state.events and not state.registration_output.exists()
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["registration", "measurement"])
async def test_checkpoint_deadline_covers_both_exchanges_and_native_disposal(
    controller_state, install_client, phase
):
    state = controller_state(checkpoint=True)
    timers = []

    def timeout(seconds):
        value = asyncio.timeout(seconds)
        timers.append(value)
        return value

    state.namespace["asyncio"] = SimpleNamespace(**{**vars(asyncio), "timeout": timeout})

    async def reply(_):
        if state.events[-1] == phase:
            timers[0].reschedule(asyncio.get_running_loop().time() + 0.01)
            await asyncio.sleep(1)
        return httpx.Response(200, stream=Stream([attestation()]))

    _, _, requests = install_client(reply)
    # Keep the descriptor-bearing cancellation on 3.12 as well as 3.13's wrapper.
    with pytest.raises(
        (ValueError, TimeoutError, CalibrationCalendarPublicationCancelled)
    ) as raised:
        await execute(state, timeout_seconds=60)
    assert timers[0].expired() and len(requests) == (1 if phase == "registration" else 2)
    failure = raised.value.__cause__ if isinstance(raised.value, TimeoutError) else raised.value
    if isinstance(failure, CalibrationCalendarPublicationCancelled):
        root = state.registration_output if phase == "registration" else state.measurement_output
        retained = json.loads((root / "publication.json").read_text(encoding="utf-8"))
        assert failure.publication_may_have_occurred is True
        assert failure.publication_sha256 == retained["publication_sha256"]
    assert not (state.output / "measurement.json").exists()
    assert_disposed(state)


@pytest.mark.asyncio
async def test_checkpoint_handle_is_not_transferable_to_another_task(
    controller_state, install_client
):
    state = controller_state(checkpoint=True)
    refused = []

    async def reply(_):
        async def borrow():
            with pytest.raises(ValueError, match="another task or process"):
                state.require_recording(state.key)
            refused.append(True)

        await asyncio.create_task(borrow())
        return httpx.Response(200, stream=Stream([attestation()]))

    install_client(reply)
    await execute(state)
    assert refused == [True, True]
    assert_disposed(state)
