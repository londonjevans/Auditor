"""Original terminal custody with isolated native fixtures, never seal or paid authority."""

from __future__ import annotations

import asyncio
import copy
import pickle
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest

import mmaudit.models.authenticated_calibration as native
import mmaudit.orchestration.calibration_calendar_controller as controller
from tests.unit.test_calibration_calendar_controller import assert_disposed
from tests.unit.test_calibration_calendar_controller import controller_state as controller_state
from tests.unit.test_calibration_checkpoint_controller import set_tip
from tests.unit.test_calibration_population_journal import read_journal
from tests.unit.test_calibration_publication import FLAGS
from tests.unit.test_opentimestamps_calendar import attestation
from tests.unit.test_opentimestamps_calendar_transport import Stream
from tests.unit.test_opentimestamps_calendar_transport import install_client as install_client
from tests.unit.test_registered_calibration_measurement import (
    measurement_protocol as measurement_protocol,
)


@pytest.fixture
def completion_state(controller_state):
    def make(count=1, **kwargs):
        state = controller_state(count, checkpoint=True, **kwargs)
        if not state.original_native:
            # Complete only the isolated native module's data API, not its production issuer.
            state.native_module.authenticated_model_calibration_bytes = (
                native.authenticated_model_calibration_bytes
            )
        return state

    return make


@pytest.mark.asyncio
@pytest.mark.parametrize("count,seeded", [(1, False), (1, True), (8, True)])
async def test_original_native_is_revoked_before_scoped_terminal_data_becomes_observable(
    completion_state, install_client, count, seeded
):
    state = completion_state(count)
    if seeded:
        set_tip(state)
    clients, _, requests = install_client(
        lambda _: httpx.Response(200, stream=Stream([attestation()]))
    )
    async with state.completion_scope(**state.args) as handle:
        assert type(handle) is controller.OwnedCheckpointCalibrationCompletion
        result = state.observe_completion(handle)
        assert type(result) is controller.CheckpointRecordedCalibrationResult
        assert not state.runner_live and all(secret.cleared for secret in state.secrets)
        assert read_journal(state.root)[-1].kind == "FINISHED"
        assert read_journal(state.root)[-1].disposition == "CONSUMED"
        assert (state.output / "measurement.json").is_file()
        assert (result.measurement.policy is not None) is (count == 8)
        assert result.measurement.calibration == state.live_measurement.calibration
        for require in (state.require, native._require_verified_authenticated_model_calibration):
            with pytest.raises(ValueError, match="absent or revoked"):
                require(state.proof, state.measured)
        with pytest.raises(ValueError, match="absent or closed"):
            controller.observe_checkpoint_calibration_completion(handle)
        for attempt in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError):
                attempt(handle)
        assert not hasattr(handle, "__dict__") and not hasattr(result, "verification")
        assert all(
            getattr(value, flag) is (flag == "external_comparison_required")
            for value in (
                result.registration.binding,
                result.registration.checkpoint,
                result.measurement_publication.binding,
                result.measurement_publication.checkpoint,
            )
            for flag in FLAGS
        )
        await asyncio.sleep(0)
        assert state.observe_completion(handle) is result
    with pytest.raises(ValueError, match="absent or closed"):
        state.observe_completion(handle)
    assert len(requests) == 2 and all(client.is_closed for client in clients)
    assert_disposed(state)


@pytest.mark.parametrize("value", [None, {}, object(), "from-disk"])
def test_constructible_values_cannot_enroll_original_completion(value):
    with pytest.raises(TypeError, match="original scope"):
        controller.OwnedCheckpointCalibrationCompletion()
    with pytest.raises(ValueError, match="absent or closed"):
        controller.observe_checkpoint_calibration_completion(value)
    with pytest.raises(ValueError, match="absent or closed"):
        controller.observe_checkpoint_calibration_completion(
            object.__new__(controller.OwnedCheckpointCalibrationCompletion)
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("consent", [False, None, 1, "true"])
async def test_completion_scope_keeps_explicit_contact_consent_before_registration(
    completion_state, install_client, consent
):
    state = completion_state()
    _, _, requests = install_client(lambda _: pytest.fail("unconsented contact"))
    with pytest.raises(ValueError):
        async with state.completion_scope(**{**state.args, "allow_calendar_contact": consent}):
            pytest.fail("completion without contact consent")
    assert not requests and not state.events
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("original", ["native", "preflight"])
async def test_completion_scope_cannot_bypass_original_production_gates(
    completion_state, install_client, original
):
    state = completion_state(**{"original_" + original: True})
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError):
        async with state.completion_scope(**state.args):
            pytest.fail("synthetic data acquired production completion")
    assert not (state.output / "measurement.json").exists()
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["calibration", "verification", "registration_sha256"])
async def test_observed_native_input_replacement_irreversibly_closes_completion(
    completion_state, install_client, field
):
    state = completion_state()
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError, match="absent or closed"):
        async with state.completion_scope(**state.args) as handle:
            original = getattr(state.live_measurement, field)
            replacement = (
                original.model_copy(deep=True)
                if field == "calibration"
                else object.__new__(native.VerifiedAuthenticatedModelCalibration)
                if field == "verification"
                else "d" * 64
            )
            object.__setattr__(state.live_measurement, field, replacement)
            with pytest.raises(ValueError, match="original native inputs changed"):
                state.observe_completion(handle)
            object.__setattr__(state.live_measurement, field, original)
            with pytest.raises(ValueError, match="absent or closed"):
                state.observe_completion(handle)
    assert_disposed(state)


@pytest.mark.asyncio
async def test_other_task_cannot_borrow_or_rehabilitate_original_completion(
    completion_state, install_client
):
    state = completion_state()
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError, match="absent or closed"):
        async with state.completion_scope(**state.args) as handle:

            async def borrow():
                with pytest.raises(ValueError, match="another task or process"):
                    state.observe_completion(handle)

            await asyncio.create_task(borrow())
            with pytest.raises(ValueError, match="absent or closed"):
                state.observe_completion(handle)
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", ["pid", "deadline", "producer", "result"])
async def test_original_completion_rejects_identity_deadline_producer_and_result_drift(
    completion_state, install_client, changed
):
    state = completion_state()
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError):
        async with state.completion_scope(**state.args) as handle:
            result = state.observe_completion(handle)
            if changed == "pid":
                state.namespace["os"] = SimpleNamespace(getpid=lambda: -1)
            elif changed == "deadline":
                state.namespace["monotonic"] = lambda: float("inf")
            elif changed == "producer":
                state.native_module._require_verified_authenticated_model_calibration = None
            else:
                object.__setattr__(result, "measurement", replace(result.measurement))
    with pytest.raises(ValueError):
        state.observe_completion(handle)
    # Restore the isolated dependency so the disposal assertion tests closed ownership itself.
    if changed == "producer":
        state.native_module._require_verified_authenticated_model_calibration = state.require
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("exception", [ValueError, asyncio.CancelledError])
async def test_exceptional_consumer_exit_invalidates_without_reviving_original_native(
    completion_state, install_client, exception
):
    state = completion_state()
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(exception, match="synthetic consumer exit"):
        async with state.completion_scope(**state.args) as handle:
            state.observe_completion(handle)
            raise exception("synthetic consumer exit")
    with pytest.raises(ValueError, match="absent or closed"):
        state.observe_completion(handle)
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["calibration", "receipt"])
async def test_equal_readback_object_substitution_is_not_original_completion_custody(
    completion_state, install_client, field
):
    state = completion_state()
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError, match="original result changed"):
        async with state.completion_scope(**state.args) as handle:
            measured = state.observe_completion(handle).measurement
            original = getattr(measured, field)
            replacement = original.model_copy(deep=True)
            assert replacement == original and replacement is not original
            object.__setattr__(measured, field, replacement)
    with pytest.raises(ValueError, match="absent or closed"):
        state.observe_completion(handle)
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_actual_consumer_timeout_or_task_cancellation_closes_every_original_owner(
    completion_state, install_client, cancel
):
    state = completion_state()
    timers = []

    def capture_timer(seconds):
        timer = asyncio.timeout(seconds)
        timers.append(timer)
        return timer

    state.namespace["asyncio"] = SimpleNamespace(**{**vars(asyncio), "timeout": capture_timer})
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    task = asyncio.current_task()
    try:
        with pytest.raises(asyncio.CancelledError if cancel else TimeoutError):
            async with state.completion_scope(**state.args) as handle:
                assert len(timers) == 1
                state.observe_completion(handle)
                if cancel:
                    task.cancel()
                else:
                    timers[0].reschedule(asyncio.get_running_loop().time() + 0.02)
                await asyncio.sleep(1)
    finally:
        if cancel:
            task.uncancel()
    with pytest.raises(ValueError, match="absent or closed"):
        state.observe_completion(handle)
    assert_disposed(state)
