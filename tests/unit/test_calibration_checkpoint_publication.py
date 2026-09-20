"""Synthetic source-owned checkpoint publication, never external seal evidence."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from decimal import Decimal
from types import SimpleNamespace

import httpx
import pytest

import mmaudit.models.calibration_checkpoint as checkpoint
import mmaudit.orchestration.calibration_calendar_publication as legacy
import mmaudit.orchestration.calibration_checkpoint_publication as publisher
import mmaudit.orchestration.calibration_publication as publication
import mmaudit.orchestration.opentimestamps_calendar_journal as journal
import mmaudit.orchestration.opentimestamps_calendar_transport as transport
from mmaudit.models.evidence_seal_authority import build_transparency_prefix_proof
from tests.unit.test_calibration_calendar_publication import registration_inputs as source_inputs
from tests.unit.test_calibration_publication import FLAGS, measured, prepare_publication
from tests.unit.test_opentimestamps_calendar import attestation
from tests.unit.test_opentimestamps_calendar_journal import reseal
from tests.unit.test_opentimestamps_calendar_transport import ORIGIN, Stream
from tests.unit.test_opentimestamps_calendar_transport import install_client as install_client
from tests.unit.test_registered_calibration_measurement import isolated_factory
from tests.unit.test_registered_calibration_measurement import (
    measurement_protocol as measurement_protocol,
)


def proof_for(subject, *, registration=None, preceding=("c" * 64,)):
    return build_transparency_prefix_proof(
        log_id_sha256="a" * 64,
        authority_subject_sha256s=(
            (*preceding, subject.subject_sha256)
            if registration is None
            else (
                *preceding,
                registration.authority_subject_sha256,
                "e" * 64,
                subject.subject_sha256,
            )
        ),
        previous_checkpoint=None if registration is None else registration.checkpoint,
    )


def registration_inputs(tmp_path):
    state = source_inputs(tmp_path)
    state.registration = publication.build_calibration_registration_publication(
        evidence_root=state.root,
        expected_registration_sha256=state.journal.registration.event_sha256,
    )
    state.registration_proof = proof_for(state.registration)
    state.prepare_registration = publisher.prepare_calibration_registration_checkpoint
    return state


def prepare_registration(state, **changes):
    args = dict(
        population_root=state.root,
        expected_registration_sha256=state.journal.registration.event_sha256,
        transparency_proof=state.registration_proof,
        expected_checkpoint_sha256=state.registration_proof.checkpoint.checkpoint_sha256,
        output_root=state.output,
        calendar_origin=ORIGIN,
    )
    args.update(changes)
    return state.prepare_registration(**args)


def read(root, pin):
    return publisher.load_calibration_checkpoint_publication(
        output_root=root, expected_publication_sha256=pin
    )


def recover(root, pin, **changes):
    args = dict(output_root=root, expected_publication_sha256=pin, allow_calendar_contact=True)
    args.update(changes)
    return publisher.recover_calibration_checkpoint_publication(**args)


def population_state(factory, count=1):
    state = prepare_publication(factory(count))
    source_module = SimpleNamespace(**vars(publication))
    source_module.build_calibration_measurement_publication = state.build_publication
    _, source_exports = isolated_factory(
        legacy, "_build_source_preparers", {"_publication": source_module}
    )
    legacy_module = SimpleNamespace(**vars(legacy))
    (
        legacy_module.prepare_calibration_registration_calendar,
        legacy_module.prepare_calibration_measurement_calendar,
    ) = source_exports
    state.namespace, exports = isolated_factory(
        publisher, "_build_checkpoint_preparers", {"_source": legacy_module}
    )
    state.prepare_registration, state.prepare_measurement = exports
    state.legacy_module, state.source_module = legacy_module, source_module
    state.output = state.root.parent / "registration-checkpoint"
    state.measurement_output = state.root.parent / "measurement-checkpoint"
    registered = state.on_registered

    def register():
        registered()
        state.registration_proof = proof_for(state.registration)
        with prepare_registration(state) as owner:
            state.registration_binding = owner.binding
        state.registration_checkpoint = read(
            state.output, state.registration_binding.publication_sha256
        ).checkpoint

    state.on_registered = register
    return state


def prepare_measurement(state, original_live, **changes):
    proof = proof_for(measured(state, original_live), registration=state.registration_proof)
    args = dict(
        live=original_live,
        ledger=state.ledger,
        population_root=state.root,
        registration_root=state.output,
        expected_registration_publication_sha256=state.registration_binding.publication_sha256,
        transparency_proof=proof,
        expected_checkpoint_sha256=proof.checkpoint.checkpoint_sha256,
        output_root=state.measurement_output,
        calendar_origin=ORIGIN,
    )
    args.update(changes)
    return state.prepare_measurement(**args)


@pytest.mark.asyncio
async def test_exact_checkpoint_source_and_nonce_are_durable_before_the_only_post(
    tmp_path, install_client
):
    state = registration_inputs(tmp_path)

    def reply(request):
        assert {p.name for p in state.output.iterdir()} == {
            "source",
            "checkpoint.json",
            "publication.json",
            "calendar",
        }
        assert {p.name for p in (state.output / "source/calendar").iterdir()} == {"000.json"}
        binding = json.loads((state.output / "publication.json").read_bytes())
        raw = (state.output / "checkpoint.json").read_bytes()
        assert hashlib.sha256(raw).hexdigest() == binding["checkpoint_file"]["sha256"]
        assert (state.output / "calendar/001.json").is_file()
        assert (
            request.method == "POST"
            and request.content.hex() == binding["preparation"]["commitment_hex"]
        )
        assert binding["preparation"]["subject_sha256"] != state.registration.subject_sha256
        return httpx.Response(200, stream=Stream([attestation()]))

    clients, _, requests = install_client(reply)
    with prepare_registration(state) as owner:
        pin = owner.binding.publication_sha256
        assert not requests
        observed = await owner.submit(allow_calendar_contact=True)
        with pytest.raises(legacy.CalibrationCalendarPublicationError):
            await owner.submit(allow_calendar_contact=True)
    assert len(requests) == 1 and all(client.is_closed for client in clients)
    assert read(state.output, pin) == observed
    assert observed.subject == state.registration
    assert observed.checkpoint.transparency_proof == state.registration_proof
    assert observed.calendar.events[-1].kind == "POST_REPLAYED"
    for value in (observed.binding, observed.checkpoint, observed.subject):
        assert all(
            getattr(value, flag) is (flag == "external_comparison_required") for flag in FLAGS
        )
    assert not hasattr(observed, "verification") and not hasattr(observed, "require")


def test_actual_prepared_requests_distinguish_same_population_same_nonce_log_forks(
    tmp_path, monkeypatch
):
    state = registration_inputs(tmp_path)
    monkeypatch.setattr(transport.secrets, "token_bytes", lambda _: b"x" * 16)
    preparations = []
    for index, preceding in enumerate(("c" * 64, "d" * 64)):
        proof = proof_for(state.registration, preceding=(preceding,))
        with prepare_registration(
            state,
            transparency_proof=proof,
            expected_checkpoint_sha256=proof.checkpoint.checkpoint_sha256,
            output_root=tmp_path / f"fork-{index}",
        ) as owner:
            preparations.append(owner.binding.preparation)
    assert preparations[0].nonce_hex == preparations[1].nonce_hex
    assert preparations[0].subject_sha256 != preparations[1].subject_sha256
    assert preparations[0].commitment_hex != preparations[1].commitment_hex


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, 8])
async def test_original_native_population_extends_the_retained_registration_checkpoint(
    measurement_protocol, install_client, count
):
    state = population_state(measurement_protocol, count)
    clients, _, requests = install_client(
        lambda _: httpx.Response(200, stream=Stream([attestation()]))
    )
    async with state.scope(**state.args) as live:
        original = live.verification
        with prepare_measurement(state, live) as owner:
            pin = owner.binding.publication_sha256
            observed = await owner.submit(allow_calendar_contact=True)
            assert observed.subject.calibration == live.calibration
            assert observed.subject.policy == live.policy
            assert (observed.subject.policy is not None) is (count == 8)
            assert (
                observed.binding.registration_publication_sha256
                == state.registration_binding.publication_sha256
            )
            assert (
                observed.checkpoint.registration_checkpoint_subject_sha256
                == state.registration_checkpoint.subject_sha256
            )
            assert (
                observed.checkpoint.transparency_proof.previous_checkpoint
                == state.registration_proof.checkpoint
            )
    assert state.closed and state.secret.cleared
    with pytest.raises(ValueError, match="absent or revoked"):
        state.require(original, state.measured)
    assert read(state.measurement_output, pin) == observed
    assert len(requests) == 1 and all(client.is_closed for client in clients)


@pytest.mark.asyncio
async def test_get_recovery_never_reconstructs_native_source_or_a_new_nonce(
    tmp_path, install_client, monkeypatch
):
    state = registration_inputs(tmp_path)
    _, _, requests = install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with prepare_registration(state) as owner:
        pin = owner.binding.publication_sha256
        first = await owner.submit(allow_calendar_contact=True)
    state.root.rename(tmp_path / "unavailable-source")
    monkeypatch.setattr(
        transport.secrets, "token_bytes", lambda _: pytest.fail("new recovery nonce")
    )
    monkeypatch.setattr(
        publication,
        "build_calibration_measurement_publication",
        lambda **_: pytest.fail("native reconstruction"),
    )
    recovered = await recover(state.output, pin)
    assert recovered.subject == first.subject and recovered.checkpoint == first.checkpoint
    assert recovered.binding == first.binding
    assert [r.method for r in requests] == ["POST", "GET"]
    assert requests[-1].url.path == "/timestamp/" + first.binding.preparation.commitment_hex
    assert not hasattr(recovered, "verification")


@pytest.mark.asyncio
@pytest.mark.parametrize("permission", [False, None, 0, 1, "true"])
async def test_contact_requires_exact_authorization_without_dispatch_intent(
    tmp_path, install_client, permission
):
    state = registration_inputs(tmp_path)
    _, _, requests = install_client(lambda _: pytest.fail("unapproved contact"))
    with prepare_registration(state) as owner:
        pin = owner.binding.publication_sha256
        with pytest.raises(ValueError, match="authorization"):
            await owner.submit(allow_calendar_contact=permission)
    with pytest.raises(ValueError, match="authorization"):
        await recover(state.output, pin, allow_calendar_contact=permission)
    assert not requests and len(read(state.output, pin).calendar.events) == 1


@pytest.mark.asyncio
async def test_prepared_only_recovery_and_legacy_entry_points_cannot_post_checkpoint(
    tmp_path, install_client
):
    state = registration_inputs(tmp_path)
    _, _, requests = install_client(lambda _: pytest.fail("prepared-only recovery dispatched"))
    with prepare_registration(state) as owner:
        pin, value = owner.binding.publication_sha256, owner._retained.checkpoint
    with pytest.raises(legacy.CalibrationCalendarPublicationError):
        await recover(state.output, pin)
    with (
        pytest.raises(ValueError, match="exact subject type"),
        journal.prepare_calibration_calendar_journal(
            evidence_root=tmp_path / "wrong-kind", subject=value, calendar_origin=ORIGIN
        ),
    ):
        pytest.fail("legacy population entry point accepted checkpoint")
    with pytest.raises(ValueError, match="exact subject type"):
        await journal.recover_calibration_calendar_journal(
            evidence_root=state.output / "calendar",
            expected_preparation_sha256=owner.binding.preparation.preparation_sha256,
            subject=value,
            calendar_origin=ORIGIN,
            allow_calendar_contact=True,
        )
    assert not requests and not (tmp_path / "wrong-kind").exists()


@pytest.mark.parametrize("change", ["pin", "proof", "population", "origin"])
def test_invalid_registration_leaves_no_dispatchable_checkpoint(tmp_path, change):
    state = registration_inputs(tmp_path)
    changes = {
        "pin": {"expected_checkpoint_sha256": "f" * 64},
        "proof": {"transparency_proof": object()},
        "population": {"expected_registration_sha256": "f" * 64},
        "origin": {"calendar_origin": "http://calendar.invalid"},
    }[change]
    with pytest.raises(ValueError), prepare_registration(state, **changes):
        pytest.fail("invalid registration input")
    assert not (state.output / "publication.json").exists()
    assert not (state.output / "calendar/001.json").exists()
    with pytest.raises(ValueError):
        read(state.output, "a" * 64)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change", ["pin", "origin", "fake_live", "proof", "fork", "missing_predecessor"]
)
async def test_measurement_refuses_wrong_original_checkpoint_or_native_custody(
    measurement_protocol, change
):
    state = population_state(measurement_protocol)
    async with state.scope(**state.args) as live:
        changes = {}
        if change == "pin":
            changes["expected_registration_publication_sha256"] = "f" * 64
        elif change == "origin":
            changes["calendar_origin"] = "https://different.invalid"
        elif change == "fake_live":
            changes["live"] = replace(live, verification=None)
        else:
            subject = measured(state, live)
            if change == "proof":
                proof = state.registration_proof
            elif change == "fork":
                prior = proof_for(state.registration, preceding=("d" * 64,))
                proof = proof_for(subject, registration=prior, preceding=("d" * 64,))
            else:
                proof = proof_for(subject)
            changes.update(
                transparency_proof=proof,
                expected_checkpoint_sha256=proof.checkpoint.checkpoint_sha256,
            )
        with pytest.raises(ValueError), prepare_measurement(state, live, **changes):
            pytest.fail("wrong predecessor/native measurement admitted")
        assert not (state.measurement_output / "publication.json").exists()
        assert not (state.measurement_output / "calendar/001.json").exists()
    assert state.closed and state.secret.cleared


@pytest.mark.asyncio
async def test_production_preparer_refuses_isolated_native_fixture(measurement_protocol):
    state = population_state(measurement_protocol)
    async with state.scope(**state.args) as live:
        state.prepare_measurement = publisher.prepare_calibration_measurement_checkpoint
        with pytest.raises(ValueError), prepare_measurement(state, live):
            pytest.fail("isolated fixture became production native authority")
        assert not (state.measurement_output / "publication.json").exists()
    assert state.closed and state.secret.cleared


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change", ["proof_revocation", "ledger", "calibration_identity", "producer"]
)
async def test_live_original_source_drift_across_await_refuses_result_and_clears_native_proof(
    measurement_protocol, install_client, change
):
    state = population_state(measurement_protocol)
    with pytest.raises(ValueError):
        async with state.scope(**state.args) as live:
            original = live.verification

            def mutate():
                if change == "proof_revocation":
                    state.revoke(original)
                elif change == "ledger":
                    charge = state.ledger.reserve("late-synthetic", Decimal("1"))
                    state.ledger.reconcile(charge, Decimal("0.1"))
                elif change == "calibration_identity":
                    object.__setattr__(live, "calibration", live.calibration.model_copy(deep=True))
                else:
                    state.legacy_module.prepare_calibration_measurement_calendar = lambda **_: None

            install_client(
                lambda _: httpx.Response(200, stream=Stream([attestation()], on_chunk=mutate))
            )
            with (
                pytest.raises(legacy.CalibrationCalendarPublicationError),
                prepare_measurement(state, live) as owner,
            ):
                await owner.submit(allow_calendar_contact=True)
            raise ValueError("synthetic consumer refused changed native source")
    assert state.closed and state.secret.cleared
    with pytest.raises(ValueError, match="absent or revoked"):
        state.require(original, state.measured)


@pytest.mark.parametrize("producer", ["registration", "measurement", "checkpoint"])
def test_original_producer_substitution_refuses_before_output(tmp_path, monkeypatch, producer):
    state = registration_inputs(tmp_path)
    module, name = {
        "registration": (legacy, "prepare_calibration_registration_calendar"),
        "measurement": (legacy, "prepare_calibration_measurement_calendar"),
        "checkpoint": (checkpoint, "build_calibration_checkpoint_subject"),
    }[producer]
    monkeypatch.setattr(module, name, lambda **_: None)
    with pytest.raises(ValueError, match="producers changed"), prepare_registration(state):
        pytest.fail("substituted original producer")
    assert not state.output.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["proof", "descriptor", "envelope"])
async def test_borrowed_in_memory_data_cannot_change_through_await(
    tmp_path, install_client, change
):
    state = registration_inputs(tmp_path)

    def mutate():
        if change == "proof":
            alternate = proof_for(state.registration, preceding=("d" * 64,))
            # A coherently self-consistent proof still differs from the original pin.
            for name in type(alternate).model_fields:
                object.__setattr__(state.registration_proof, name, getattr(alternate, name))
        elif change == "descriptor":
            object.__setattr__(owner.binding, "registration_event_sha256", "f" * 64)
        else:
            object.__setattr__(owner._retained.checkpoint, "population_subject_sha256", "f" * 64)

    clients, _, requests = install_client(
        lambda _: httpx.Response(200, stream=Stream([attestation()], on_chunk=mutate))
    )
    with (
        pytest.raises(legacy.CalibrationCalendarPublicationError),
        prepare_registration(state) as owner,
    ):
        await owner.submit(allow_calendar_contact=True)
    assert len(requests) == 1 and all(client.is_closed for client in clients)


@pytest.mark.parametrize("flag", FLAGS)
def test_new_descriptor_never_grants_authority_even_when_rehashed(tmp_path, flag):
    state = registration_inputs(tmp_path)
    with prepare_registration(state) as owner:
        payload = owner.binding.model_dump(mode="json")
    payload[flag] = not payload[flag]
    with pytest.raises(ValueError):
        publisher.CalibrationCheckpointCalendarBinding.model_validate_json(
            reseal(payload, "publication_sha256")
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("cancelled", [False, True])
async def test_interrupted_post_retains_new_descriptor_and_can_only_recover_by_get(
    tmp_path, install_client, cancelled
):
    state = registration_inputs(tmp_path)
    failure = asyncio.CancelledError() if cancelled else RuntimeError("synthetic interrupted reply")
    clients, _, requests = install_client(
        lambda _: httpx.Response(200, stream=Stream(failure=failure))
    )
    expected = (
        legacy.CalibrationCalendarPublicationCancelled
        if cancelled
        else legacy.CalibrationCalendarPublicationError
    )
    with prepare_registration(state) as owner:
        pin = owner.binding.publication_sha256
        with pytest.raises(expected) as caught:
            await owner.submit(allow_calendar_contact=True)
        assert caught.value.publication_sha256 == pin and caught.value.publication_may_have_occurred
    assert read(state.output, pin).calendar.events[-1].kind == "POST_UNCERTAIN"
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    result = await recover(state.output, pin)
    assert result.calendar.events[-1].kind == "LOOKUP_REPLAYED"
    assert [r.method for r in requests] == ["POST", "GET"]
    assert all(client.is_closed for client in clients)
