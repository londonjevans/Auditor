"""Source-owned handoff tests with isolated native leases, never REAL publication evidence."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import fields, replace
from decimal import Decimal
from types import SimpleNamespace

import httpx
import pytest

import mmaudit.orchestration.calibration_calendar_publication as publisher
import mmaudit.orchestration.calibration_publication as publication
import mmaudit.orchestration.opentimestamps_calendar_transport as transport
from mmaudit.orchestration.calibration_population import CalibrationPopulationJournal
from mmaudit.reporting.json_report import stable_json
from tests.unit.test_calibration_population_journal import journal_inputs, registrations
from tests.unit.test_calibration_publication import FLAGS, prepare_publication
from tests.unit.test_opentimestamps_calendar import attestation
from tests.unit.test_opentimestamps_calendar_journal import reseal
from tests.unit.test_opentimestamps_calendar_transport import ORIGIN, Stream
from tests.unit.test_opentimestamps_calendar_transport import install_client as install_client
from tests.unit.test_registered_calibration_measurement import isolated_factory
from tests.unit.test_registered_calibration_measurement import (
    measurement_protocol as measurement_protocol,
)


def registration_inputs(tmp_path):
    root, plan, ledger = journal_inputs(tmp_path)
    population = CalibrationPopulationJournal(
        evidence_root=root,
        selection_plan=plan,
        ledger=ledger,
        present_registries=registrations(plan),
    )
    return SimpleNamespace(
        root=root,
        plan=plan,
        ledger=ledger,
        journal=population,
        output=tmp_path / "publication",
    )


def prepare_registration(state, **changes):
    arguments = dict(
        population_root=state.root,
        expected_registration_sha256=state.journal.registration.event_sha256,
        output_root=state.output,
        calendar_origin=ORIGIN,
    )
    arguments.update(changes)
    return publisher.prepare_calibration_registration_calendar(**arguments)


def read(output, pin):
    return publisher.load_calibration_calendar_publication(
        output_root=output, expected_publication_sha256=pin
    )


def recover(output, pin, **changes):
    arguments = dict(
        output_root=output, expected_publication_sha256=pin, allow_calendar_contact=True
    )
    arguments.update(changes)
    return publisher.recover_calibration_calendar_publication(**arguments)


def population_state(factory, count=1):
    state = prepare_publication(factory(count))
    source_module = SimpleNamespace(**vars(publication))
    source_module.build_calibration_measurement_publication = state.build_publication
    namespace, exports = isolated_factory(
        publisher, "_build_source_preparers", {"_publication": source_module}
    )
    state.publisher_namespace = namespace
    state.publisher_source_module = source_module
    state.registration_output = state.root.parent / "registration-publication"
    state.measurement_output = state.root.parent / "measurement-publication"
    state.prepare_registration, state.prepare_measurement = exports
    original_registered = state.on_registered

    def register():
        original_registered()
        with state.prepare_registration(
            population_root=state.root,
            expected_registration_sha256=state.journal.registration.event_sha256,
            output_root=state.registration_output,
            calendar_origin=ORIGIN,
        ) as owner:
            state.registration_binding = owner.binding
        # An offline descriptor is explicitly not a pre-dispatch external publication.
        assert (
            read(
                state.registration_output, state.registration_binding.publication_sha256
            ).calendar.detached_proof
            is None
        )

    state.on_registered = register
    return state


def prepare_measurement(state, original_live, **changes):
    arguments = dict(
        live=original_live,
        ledger=state.ledger,
        population_root=state.root,
        registration_root=state.registration_output,
        expected_registration_publication_sha256=state.registration_binding.publication_sha256,
        output_root=state.measurement_output,
        calendar_origin=ORIGIN,
    )
    arguments.update(changes)
    return state.prepare_measurement(**arguments)


@pytest.mark.asyncio
async def test_original_registration_subject_and_descriptor_are_retained_before_dispatch(
    tmp_path, install_client
):
    state = registration_inputs(tmp_path)

    def reply(request):
        assert {path.name for path in state.output.iterdir()} == {
            "subject.json",
            "publication.json",
            "calendar",
        }
        descriptor = json.loads((state.output / "publication.json").read_bytes())
        raw = (state.output / "subject.json").read_bytes()
        assert hashlib.sha256(raw).hexdigest() == descriptor["subject_file"]["sha256"]
        assert descriptor["publication_sha256"] == pin
        assert (state.output / "calendar/001.json").is_file()
        assert request.content.hex() == descriptor["preparation"]["commitment_hex"]
        assert len(request.content) == 32 and request.method == "POST"
        return httpx.Response(200, stream=Stream([attestation()]))

    clients, _, requests = install_client(reply)
    with prepare_registration(state) as owner:
        pin = owner.binding.publication_sha256
        assert owner.binding.registration_event_sha256 == state.journal.registration.event_sha256
        assert not requests
        result = await owner.submit(allow_calendar_contact=True)
    assert len(requests) == 1 and all(client.is_closed for client in clients)
    assert result == read(state.output, pin)
    assert result.subject.population_events == (state.journal.registration,)
    assert result.calendar.events[-1].kind == "POST_REPLAYED"
    assert all(
        getattr(result.binding, flag) is (flag == "external_comparison_required") for flag in FLAGS
    )
    assert not hasattr(result, "verification") and not hasattr(result, "require")


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, 8])
async def test_live_full_population_and_original_policy_or_refusal_join_registration(
    measurement_protocol, install_client, count
):
    state = population_state(measurement_protocol, count)
    clients, _, requests = install_client(
        lambda _: httpx.Response(200, stream=Stream([attestation()]))
    )
    async with state.scope(**state.args) as live:
        state.proof = live.verification
        with prepare_measurement(state, live) as owner:
            pin = owner.binding.publication_sha256
            result = await owner.submit(allow_calendar_contact=True)
            assert result.subject.calibration is not None
            assert result.subject.calibration == live.calibration
            assert result.subject.policy == live.policy
            assert (result.subject.policy is not None) == (count == 8)
            assert (
                result.binding.registration_publication_sha256
                == state.registration_binding.publication_sha256
            )
    assert state.closed and state.secret.cleared
    with pytest.raises(ValueError, match="absent or revoked"):
        state.require(state.proof, state.measured)
    assert read(state.measurement_output, pin) == result
    assert len(requests) == 1 and all(c.is_closed for c in clients)


@pytest.mark.asyncio
async def test_recovery_uses_retained_subject_without_reconstructing_live_source_or_entropy(
    tmp_path, install_client, monkeypatch
):
    state = registration_inputs(tmp_path)
    _, _, requests = install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with prepare_registration(state) as owner:
        pin = owner.binding.publication_sha256
        first = await owner.submit(allow_calendar_contact=True)
    (state.root / "000.json").write_bytes(b"original source is no longer available")
    monkeypatch.setattr(transport.secrets, "token_bytes", lambda _: pytest.fail("recovery entropy"))
    monkeypatch.setattr(
        publication,
        "build_calibration_measurement_publication",
        lambda **_: pytest.fail("native reconstruction"),
    )
    recovered = await recover(state.output, pin)
    assert recovered.subject == first.subject and recovered.binding == first.binding
    assert [r.method for r in requests] == ["POST", "GET"]
    assert requests[1].url.path == "/timestamp/" + first.binding.preparation.commitment_hex
    assert not hasattr(recovered, "verification")
    assert recovered.binding.external_publication_verified is False


@pytest.mark.asyncio
@pytest.mark.parametrize("flag", [False, None, 0, 1, "true"])
async def test_contact_permission_refuses_without_a_dispatch_intent(tmp_path, install_client, flag):
    state = registration_inputs(tmp_path)
    _, _, requests = install_client(lambda _: pytest.fail("unapproved calendar contact"))
    with prepare_registration(state) as owner:
        pin = owner.binding.publication_sha256
        with pytest.raises(ValueError, match="authorization"):
            await owner.submit(allow_calendar_contact=flag)
    assert len(read(state.output, pin).calendar.events) == 1 and not requests
    with pytest.raises(ValueError, match="authorization"):
        await recover(state.output, pin, allow_calendar_contact=flag)


@pytest.mark.parametrize("origin", ["http://calendar.invalid", ORIGIN + "/path", "", None])
def test_invalid_origin_does_not_create_an_output(tmp_path, origin):
    state = registration_inputs(tmp_path)
    with pytest.raises(ValueError), prepare_registration(state, calendar_origin=origin):
        pytest.fail("invalid origin admitted")
    assert not state.output.exists()


@pytest.mark.parametrize(
    "name",
    [
        "build_calibration_registration_publication",
        "build_calibration_measurement_publication",
        "_retained_journal",
        "_require_journal",
    ],
)
def test_original_producer_substitution_refuses_before_output(tmp_path, monkeypatch, name):
    state = registration_inputs(tmp_path)
    monkeypatch.setattr(publication, name, lambda **_: None)
    with pytest.raises(ValueError, match="producers changed"), prepare_registration(state):
        pytest.fail("substituted source producer")
    assert not state.output.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    ["calibration_identity", "proof", "ledger", "live_field", "registration_file", "producer"],
)
async def test_live_source_change_across_await_refuses_handoff_and_disposes_native_proof(
    measurement_protocol, install_client, change
):
    state = population_state(measurement_protocol)
    with pytest.raises(ValueError):
        async with state.scope(**state.args) as live:
            state.proof = live.verification

            def mutate():
                if change == "calibration_identity":
                    object.__setattr__(live, "calibration", live.calibration.model_copy(deep=True))
                elif change == "proof":
                    state.revoke(live.verification)
                elif change == "ledger":
                    reserved = state.ledger.reserve("synthetic-late", Decimal("1"))
                    state.ledger.reconcile(reserved, Decimal("0.1"))
                elif change == "live_field":
                    object.__setattr__(live, "registration_sha256", "f" * 64)
                elif change == "producer":
                    state.publisher_source_module.build_calibration_measurement_publication = (
                        lambda **_: None
                    )
                else:
                    path = state.registration_output / "subject.json"
                    path.write_bytes(path.read_bytes() + b"\n")

            install_client(
                lambda _: httpx.Response(200, stream=Stream([attestation()], on_chunk=mutate))
            )
            with (
                pytest.raises(publisher.CalibrationCalendarPublicationError),
                prepare_measurement(state, live) as owner,
            ):
                await owner.submit(allow_calendar_contact=True)
            raise ValueError("synthetic consumer refused changed live source")
    assert state.closed and state.secret.cleared
    with pytest.raises(ValueError, match="absent or revoked"):
        state.require(state.proof, state.measured)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["pin", "origin", "registration", "fake_live", "missing_proof"])
async def test_wrong_predecessor_or_native_input_refuses_before_any_new_output(
    measurement_protocol, tmp_path, change
):
    state = population_state(measurement_protocol)
    async with state.scope(**state.args) as live:
        changes = {}
        if change == "pin":
            changes["expected_registration_publication_sha256"] = "f" * 64
        elif change == "origin":
            changes["calendar_origin"] = "https://different.invalid"
        elif change == "registration":
            other_root = tmp_path / "other"
            other_root.mkdir(mode=0o700)
            other = registration_inputs(other_root)
            with prepare_registration(other) as owner:
                pin = owner.binding.publication_sha256
            changes.update(
                registration_root=other.output, expected_registration_publication_sha256=pin
            )
        elif change == "fake_live":
            changes["live"] = SimpleNamespace(
                **{field.name: getattr(live, field.name) for field in fields(live)}
            )
        else:
            changes["live"] = replace(live, verification=None)
        with pytest.raises(ValueError), prepare_measurement(state, live, **changes):
            pytest.fail("wrong source admitted")
        assert not state.measurement_output.exists()


@pytest.mark.asyncio
async def test_original_native_producer_rejects_isolated_structural_measurement(
    measurement_protocol,
):
    state = population_state(measurement_protocol)
    async with state.scope(**state.args) as live:
        with (
            pytest.raises(ValueError),
            publisher.prepare_calibration_measurement_calendar(
                live=live,
                ledger=state.ledger,
                population_root=state.root,
                registration_root=state.registration_output,
                expected_registration_publication_sha256=state.registration_binding.publication_sha256,
                output_root=state.measurement_output,
                calendar_origin=ORIGIN,
            ),
        ):
            pytest.fail("synthetic proof became original native custody")
    assert not state.measurement_output.exists() and state.closed and state.secret.cleared


@pytest.mark.parametrize("flag", FLAGS)
@pytest.mark.parametrize("value", ["opposite", 0, 1])
def test_descriptor_data_never_grants_authority(tmp_path, flag, value):
    state = registration_inputs(tmp_path)
    with prepare_registration(state) as owner:
        payload = owner.binding.model_dump(mode="json")
    payload[flag] = not payload[flag] if value == "opposite" else value
    with pytest.raises(ValueError):
        publisher.CalibrationCalendarPublicationBinding.model_validate_json(
            reseal(payload, "publication_sha256")
        )


@pytest.mark.parametrize(
    "change", ["path", "size", "phase", "predecessor", "directory", "hash", "extra"]
)
def test_coherently_rehashed_descriptor_still_requires_exact_profile(tmp_path, change):
    state = registration_inputs(tmp_path)
    with prepare_registration(state) as owner:
        payload = owner.binding.model_dump(mode="json")
    if change == "path":
        payload["subject_file"]["path"] = "different.json"
    elif change == "size":
        payload["subject_file"]["size"] = 66_000_001
    elif change == "phase":
        payload["preparation"]["phase"] = "MEASURED_POPULATION"
        payload["preparation"] = json.loads(reseal(payload["preparation"], "preparation_sha256"))
    elif change == "predecessor":
        payload["registration_publication_sha256"] = "a" * 64
    elif change == "directory":
        payload["calendar_directory"] = "different"
    elif change == "hash":
        payload["publication_sha256"] = "b" * 64
    else:
        payload["unexpected"] = "value"
    raw = stable_json(payload) if change == "hash" else reseal(payload, "publication_sha256")
    with pytest.raises(ValueError):
        publisher.CalibrationCalendarPublicationBinding.model_validate_json(raw)


@pytest.mark.asyncio
@pytest.mark.parametrize("cancelled", [False, True])
async def test_failure_or_cancellation_retains_descriptor_and_uncertain_child_attempt(
    tmp_path, install_client, cancelled
):
    state = registration_inputs(tmp_path)
    failure = asyncio.CancelledError() if cancelled else RuntimeError("synthetic stream failure")
    clients, _, requests = install_client(
        lambda _: httpx.Response(200, stream=Stream(failure=failure))
    )
    expected = (
        publisher.CalibrationCalendarPublicationCancelled
        if cancelled
        else publisher.CalibrationCalendarPublicationError
    )
    with prepare_registration(state) as owner:
        pin = owner.binding.publication_sha256
        with pytest.raises(expected) as caught:
            await owner.submit(allow_calendar_contact=True)
        assert caught.value.publication_sha256 == pin and caught.value.publication_may_have_occurred
    assert read(state.output, pin).calendar.events[-1].kind == "POST_UNCERTAIN"
    assert len(requests) == 1 and all(c.is_closed for c in clients)


def test_original_producer_code_drift_is_not_hidden_by_same_function_identity(
    tmp_path, monkeypatch
):
    state = registration_inputs(tmp_path)

    def replacement(**_kwargs):
        return None

    monkeypatch.setattr(
        publication.build_calibration_registration_publication, "__code__", replacement.__code__
    )
    with pytest.raises(ValueError, match="producers changed"), prepare_registration(state):
        pytest.fail("modified original producer code")
    assert not state.output.exists()


@pytest.mark.asyncio
async def test_equivalent_new_verification_cannot_replace_the_borrowed_live_proof(
    measurement_protocol, install_client
):
    state = population_state(measurement_protocol)
    alternate = None
    async with state.scope(**state.args) as live:
        original = live.verification

        def mutate():
            nonlocal alternate
            calibration, alternate = state.native_module.observe_authenticated_model_calibration(
                selected_model_ids=live.calibration.selected_model_ids,
                benchmark_suite=None,
                ground_truth=None,
                inputs=(),
            )
            assert calibration == live.calibration and alternate is not original
            state.require(alternate, calibration)
            object.__setattr__(live, "verification", alternate)

        install_client(
            lambda _: httpx.Response(200, stream=Stream([attestation()], on_chunk=mutate))
        )
        try:
            with (
                pytest.raises(publisher.CalibrationCalendarPublicationError),
                prepare_measurement(state, live) as owner,
            ):
                await owner.submit(allow_calendar_contact=True)
        finally:
            object.__setattr__(live, "verification", original)
            if alternate is not None:
                state.revoke(alternate)
    assert alternate is not None and state.closed and state.secret.cleared


@pytest.mark.asyncio
async def test_revoked_native_proof_at_scope_exit_prevents_handoff(measurement_protocol):
    state = population_state(measurement_protocol)
    with pytest.raises(ValueError):
        async with state.scope(**state.args) as live:
            state.proof = live.verification
            with prepare_measurement(state, live):
                state.revoke(live.verification)
    assert state.closed and state.secret.cleared


@pytest.mark.asyncio
async def test_measurement_descriptor_cannot_substitute_for_registration(measurement_protocol):
    state = population_state(measurement_protocol)
    async with state.scope(**state.args) as live:
        with prepare_measurement(state, live) as owner:
            pin = owner.binding.publication_sha256
        output = state.root.parent / "wrong-phase"
        with (
            pytest.raises(ValueError, match="registration descriptor"),
            prepare_measurement(
                state,
                live,
                registration_root=state.measurement_output,
                expected_registration_publication_sha256=pin,
                output_root=output,
            ),
        ):
            pytest.fail("measurement was adopted as registration")
        assert not output.exists()


@pytest.mark.parametrize("pin", [None, True, "A" * 64, "f" * 63, "f" * 64 + "\n"])
def test_recovery_pin_requires_exact_original_bytes_before_file_access(tmp_path, pin):
    with pytest.raises(ValueError, match="externally retained"):
        read(tmp_path / "absent", pin)


@pytest.mark.asyncio
async def test_in_memory_descriptor_change_cannot_dispatch(tmp_path, install_client):
    state = registration_inputs(tmp_path)
    _, _, requests = install_client(lambda _: pytest.fail("mutated descriptor dispatched"))
    with pytest.raises(ValueError), prepare_registration(state) as owner:
        object.__setattr__(owner.binding, "registration_event_sha256", "b" * 64)
        await owner.submit(allow_calendar_contact=True)
    assert not requests
