"""Actual registered batch/controller flow with explicitly isolated native test leases.

Only runner/preflight/native issuers are synthetic stand-ins. Original population,
batch, accounting, measurement and publication orchestration perform their real
local I/O and cleanup. Production native verification still rejects these fixtures.
"""

from __future__ import annotations

import asyncio
import json
import os
import pickle
from contextlib import asynccontextmanager
from dataclasses import replace
from decimal import Decimal
from types import SimpleNamespace

import httpx
import pytest

import mmaudit.models.calibration_checkpoint as checkpoint_model
import mmaudit.orchestration.authenticated_calibration_accounting as accounting
import mmaudit.orchestration.authenticated_calibration_measurement as measurement
import mmaudit.orchestration.authenticated_calibration_openrouter as batch
import mmaudit.orchestration.calibration_calendar_controller as controller
import mmaudit.orchestration.calibration_calendar_publication as publisher
import mmaudit.orchestration.calibration_checkpoint_publication as checkpoint_publisher
import mmaudit.orchestration.calibration_publication as publication
from mmaudit.models.authenticated_runner import (
    begin_cross_lineage_ledger_interval,
    close_cross_lineage_ledger_interval,
    require_verified_cross_lineage_runner_custody,
)
from mmaudit.models.authenticated_runner_execution import CrossLineageAdjudicationRunKind
from mmaudit.models.authenticated_runner_ledger import (
    _decimal_text,
    _entry_sha256,
    _snapshot_sha256,
)
from mmaudit.operator_secrets import OperatorSecrets
from tests.authenticated_calibration_support import reseal_source
from tests.unit.test_authenticated_calibration import measure
from tests.unit.test_authenticated_runner_openrouter import (
    _completed_execution,
    _execution_inventory,
    _structural_launch,
)
from tests.unit.test_calibration_population_journal import read_journal
from tests.unit.test_calibration_publication import FLAGS, prepare_publication
from tests.unit.test_opentimestamps_calendar import PENDING, attestation, blob
from tests.unit.test_opentimestamps_calendar_transport import ORIGIN, Stream
from tests.unit.test_opentimestamps_calendar_transport import install_client as install_client
from tests.unit.test_registered_calibration_measurement import isolated_factory
from tests.unit.test_registered_calibration_measurement import (
    measurement_protocol as measurement_protocol,
)
from tests.unit.test_registered_calibration_scope import DeclaredData

ORIGINAL_PREFLIGHT = batch.preflight_authenticated_openrouter_launch


@pytest.fixture
def controller_state(measurement_protocol, monkeypatch):
    def make(count=1, *, original_native=False, original_preflight=False, checkpoint=False):
        state = prepare_publication(measurement_protocol(count, original_native=original_native))
        state.events, state.rebound, state.executions = [], [], []
        state.runner_live = {}
        state.fail_preflight = state.fail_runner = state.fail_cleanup = None
        state.on_preflight = state.on_runner = state.on_cleanup = None
        state.on_measurement = state.on_readback = None
        state.key = None
        state.registration_output = state.root.parent / "registration-calendar"
        state.measurement_output = state.root.parent / "measurement-calendar"
        shared = DeclaredData(label="synthetic-common-config-policy-corpus")
        base = _structural_launch()
        state.launches = tuple(
            replace(
                base,
                config=shared,
                benchmark_suite=shared,
                qualification_policy=shared,
                candidate_registry=DeclaredData(
                    label=source.collision_map.candidate.exact_model_id,
                    registry_sha256=source.runs[0].candidate_registry_sha256,
                    candidates=(
                        SimpleNamespace(
                            exact_model_id=source.collision_map.candidate.exact_model_id
                        ),
                    ),
                ),
                candidate_discovery_manifest=shared,
                budget=SimpleNamespace(atomic_ledger=state.ledger),
                run_plans=tuple(
                    SimpleNamespace(
                        run_kind=kind,
                        judge_registry=shared,
                        judge_discovery_manifest=shared,
                        judge_discovery_evidence=(),
                        candidate_declared_cost_cap_usd_per_attempt=Decimal("1"),
                        judge_declared_cost_cap_usd_per_attempt=Decimal("1"),
                    )
                    for kind in (
                        CrossLineageAdjudicationRunKind.PRIMARY,
                        CrossLineageAdjudicationRunKind.REPLAY,
                    )
                ),
            )
            for source in state.sources
        )
        state.secrets = (
            state.secret,
            *(
                OperatorSecrets({"OPENROUTER_API_KEY": "synthetic-controller-key"})
                for _ in range(count - 1)
            ),
        )

        def preflight(launch):
            index = state.launches.index(launch)
            state.events.append(f"preflight-{index}")
            assert read_journal(state.root)[0].kind == "REGISTERED"
            assert (state.registration_output / "calendar/002.json").is_file()
            if state.on_preflight is not None:
                state.on_preflight(index)
            if original_preflight:
                return ORIGINAL_PREFLIGHT(launch)
            if state.fail_preflight == index:
                raise ValueError("synthetic preflight refusal")
            return _execution_inventory()

        @asynccontextmanager
        async def runner(*, launch, operator_secrets, _accounting):
            index = state.launches.index(launch)
            state.events.append(f"runner-{index}")
            opened = begin_cross_lineage_ledger_interval(state.ledger)
            initial = state.ledger.snapshot()
            if state.fail_runner == index:
                charge = state.ledger.reserve(f"synthetic-uncertain-{index}", Decimal("1"))
                state.ledger.commit_for_transport(charge)
                state.ledger.reconcile(charge, None)
                operator_secrets.clear()
                raise ValueError("synthetic runner failed with uncertain billing")
            payload = state.sources[index].model_dump(mode="json")
            interval = payload["runner_evidence"]["ledger_interval"]
            for entry in interval["entries"]:
                charge = state.ledger.reserve(
                    entry["request_id"], Decimal(entry["reserved_usd"] or "1")
                )
                state.ledger.reconcile(charge, Decimal(entry["actual_cost_usd"]))
            final = state.ledger.snapshot()
            actual = {entry.request_id: entry for entry in final.entries}
            for entry in interval["entries"]:
                entry["entry_sha256"] = _entry_sha256(actual[entry["request_id"]])
                entry["reserved_usd"] = _decimal_text(actual[entry["request_id"]].reserved_usd)
            interval.update(
                ledger_identity_sha256=state.ledger.identity_sha256,
                initial_snapshot_sha256=_snapshot_sha256(initial),
                final_snapshot_sha256=_snapshot_sha256(final),
                initial_spent_usd=_decimal_text(initial.spent_usd),
                final_spent_usd=_decimal_text(final.spent_usd),
            )
            source = reseal_source(payload)
            closed = close_cross_lineage_ledger_interval(
                opened,
                expected_request_ids=tuple(entry["request_id"] for entry in interval["entries"]),
            )
            prefix = accounting.retain_calibration_ledger_interval(_accounting, interval=closed)
            execution = replace(
                _completed_execution(),
                closed_ledger_interval=closed,
                runner_evidence=source.runner_evidence,
            )
            state.rebound.append(source)
            state.executions.append(execution)
            state.runner_live[execution.runner_capability] = (execution, prefix)
            operator_secrets.clear()
            try:
                if state.on_runner is not None:
                    state.on_runner(index)
                if len(state.rebound) == count:
                    state.measured = measure(tuple(state.rebound))
                yield execution
            finally:
                state.events.append(f"dispose-{index}")
                state.runner_live.pop(execution.runner_capability)
                accounting.observe_calibration_ledger_accounting(_accounting)
                if state.on_cleanup is not None:
                    state.on_cleanup(index)
                if state.fail_cleanup == index:
                    raise ValueError("synthetic cleanup refusal")

        def require_runner(execution):
            original, prefix = state.runner_live[execution.runner_capability]
            assert execution is original
            accounting.require_calibration_ledger_prefix(prefix)

        monkeypatch.setattr(batch, "preflight_authenticated_openrouter_launch", preflight)
        monkeypatch.setattr(batch, "_owned_authenticated_openrouter_runner_scope", runner)
        monkeypatch.setattr(batch, "_require_live_runner_consumption", require_runner)

        # Use the ACTUAL registered batch, not measurement_protocol's alternate batch fixture.
        state.measurement_namespace, state.scope = isolated_factory(
            measurement, "_build_registered_measurement_scope", {"_native": state.native_module}
        )
        assert (
            state.measurement_namespace["_owned_registered_calibration_scope"]
            is batch._owned_registered_calibration_scope
        )
        measured_module = SimpleNamespace(**vars(measurement))
        measured_module.registered_calibration_measurement_scope = state.scope

        def readback(**arguments):
            result = measurement.load_registered_calibration_measurement(**arguments)
            if state.on_readback is not None:
                state.on_readback()
            return result

        measured_module.load_registered_calibration_measurement = readback
        source_module = SimpleNamespace(**vars(publication))
        source_module.build_calibration_measurement_publication = state.build_publication
        _, preparers = isolated_factory(
            publisher, "_build_source_preparers", {"_publication": source_module}
        )
        publisher_module = SimpleNamespace(**vars(publisher))
        (
            publisher_module.prepare_calibration_registration_calendar,
            publisher_module.prepare_calibration_measurement_calendar,
        ) = preparers
        checkpoint_publisher_module = SimpleNamespace(**vars(checkpoint_publisher))
        _, checkpoint_preparers = isolated_factory(
            checkpoint_publisher, "_build_checkpoint_preparers", {"_source": publisher_module}
        )
        (
            checkpoint_publisher_module.prepare_calibration_registration_checkpoint,
            checkpoint_publisher_module.prepare_calibration_measurement_checkpoint,
        ) = checkpoint_preparers
        checkpoint_module = SimpleNamespace(**vars(checkpoint_model))
        state.namespace, exports = isolated_factory(
            controller,
            "_build_calendar_controller",
            {
                "_measurement": measured_module,
                "_publication": publisher_module,
                "_checkpoint_publication": checkpoint_publisher_module,
                "_population_publication": source_module,
                "_checkpoint": checkpoint_module,
                "_native": state.native_module,
            },
        )
        (
            state.execute,
            register,
            record_measurement,
            state.require_recording,
            state.execute_checkpoint,
            state.completion_scope,
            state.observe_completion,
        ) = exports
        if checkpoint:
            state.execute = state.execute_checkpoint
            state.args.update(
                transparency_log_id_sha256="a" * 64,
                initial_transparency_proof=None,
                expected_initial_checkpoint_sha256=None,
            )
        state.checkpoint_publisher_module = checkpoint_publisher_module
        state.checkpoint_module, state.population_module = checkpoint_module, source_module
        state.record_registration, state.record_measurement = register, record_measurement
        state.publisher_module, state.measured_module = publisher_module, measured_module

        async def registered(key, journal):
            state.key, state.journal = key, journal
            state.events.append("registration")
            await register(key, journal)

        async def measured(key, live):
            state.live_measurement = live
            state.proof = live.verification
            state.events.append("measurement")
            if state.on_measurement is not None:
                state.on_measurement(live)
            await record_measurement(key, live)

        # Only test-owned lifecycle exports are substituted; original native issuers are not.
        monkeypatch.setattr(controller, "_record_calendar_registration", registered)
        monkeypatch.setattr(controller, "_record_calendar_measurement", measured)
        monkeypatch.setattr(controller, "_require_calendar_recording", state.require_recording)
        state.args.update(launches=state.launches, operator_secrets=state.secrets)
        state.args.update(
            registration_publication_root=state.registration_output,
            measurement_publication_root=state.measurement_output,
            calendar_origin=ORIGIN,
            allow_calendar_contact=True,
        )
        return state

    return make


async def execute(state, **changes):
    return await state.execute(**{**state.args, **changes})


def assert_disposed(state):
    assert not state.runner_live
    assert all(secret.cleared for secret in state.secrets)
    if state.key is not None:
        with pytest.raises(ValueError, match="absent or closed"):
            state.require_recording(state.key)
    if state.proof is not None and not state.original_native:
        with pytest.raises(ValueError, match="absent or revoked"):
            state.require(state.proof, state.measured)


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, 8])
async def test_actual_registration_and_measurement_boundaries_preserve_full_population(
    controller_state, install_client, count
):
    state = controller_state(count)

    def reply(request):
        kinds = [event.kind for event in read_journal(state.root)]
        assert request.method == "POST" and len(request.content) == 32
        if state.events[-1] == "registration":
            assert kinds == ["REGISTERED"]
            assert not any(event.startswith("preflight") for event in state.events)
        else:
            assert state.events[-1] == "measurement"
            assert kinds[-1] == "RUNNER_RETAINED"
            assert all(slot.state == "RETAINED" for slot in read_journal(state.root)[-1].slots)
            state.require(state.proof, state.measured)
        return httpx.Response(200, stream=Stream([attestation()]))

    clients, _, requests = install_client(reply)
    result = await execute(state)
    assert len(requests) == 2 and all(client.is_closed for client in clients)
    assert result.measurement.calibration.selected_model_ids == tuple(
        entry.exact_model_id for entry in state.plan.entries
    )
    assert (result.measurement.policy is not None) == (count == 8)
    assert result.measurement_publication.subject.calibration == result.measurement.calibration
    assert (
        result.measurement_publication.binding.registration_publication_sha256
        == result.registration.binding.publication_sha256
    )
    assert read_journal(state.root)[-1].disposition == "CONSUMED"
    assert all(
        getattr(observation.binding, flag) is (flag == "external_comparison_required")
        for observation in (result.registration, result.measurement_publication)
        for flag in FLAGS
    )
    assert not hasattr(result, "verification")
    assert state.events[: count + 1] == ["registration"] + [f"preflight-{i}" for i in range(count)]
    assert state.events[-count:] == [f"dispose-{i}" for i in reversed(range(count))]
    for execution in state.executions:
        with pytest.raises(ValueError):
            require_verified_cross_lineage_runner_custody(
                execution.runner_capability, evidence=execution.runner_evidence
            )
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["registration", "measurement"])
@pytest.mark.parametrize("outcome", ["http_error", "invalid", "cancel"])
async def test_exchange_failure_stops_the_recording_path_without_retry_or_completion(
    controller_state, install_client, phase, outcome
):
    state = controller_state()

    def reply(_request):
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
        assert len(state.ledger.snapshot().entries) == 1
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["preflight", "runner", "cleanup"])
async def test_original_failure_and_uncertain_billing_are_not_converted_to_success(
    controller_state, install_client, failure
):
    state = controller_state(3)
    setattr(state, "fail_" + failure, 1)
    _, _, requests = install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError):
        await execute(state)
    assert read_journal(state.root)[-1].disposition == "FAILED"
    assert len(read_journal(state.root)[-1].slots) == 3
    assert len(requests) == (2 if failure == "cleanup" else 1)
    assert not (state.output / "measurement.json").exists()
    if failure == "runner":
        assert state.ledger.snapshot().entries[-1].actual_cost_usd is None
        assert "runner-2" not in state.events
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("allow", [False, None, 0, 1, "true"])
async def test_contact_consent_is_exact_and_precedes_registration_or_owned_output(
    controller_state, install_client, allow
):
    state = controller_state()
    _, _, requests = install_client(lambda _: pytest.fail("no contact authorized"))
    with pytest.raises(ValueError):
        await execute(state, allow_calendar_contact=allow)
    assert not requests and not state.events
    assert not tuple(state.root.iterdir()) and not tuple(state.output.iterdir())
    assert not state.registration_output.exists()
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("deadline", [True, 0, -1, 86401, float("nan"), float("inf")])
async def test_invalid_overall_deadline_cannot_enter_registration(controller_state, deadline):
    state = controller_state()
    with pytest.raises(ValueError, match="deadline"):
        await execute(state, timeout_seconds=deadline)
    assert not state.events and not state.registration_output.exists()
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["registration", "measurement"])
async def test_whole_deadline_includes_calendar_waits_and_disposes_every_owner(
    controller_state, install_client, boundary
):
    state = controller_state()
    timers, reached = [], []

    def timeout(seconds):
        value = asyncio.timeout(seconds)
        timers.append(value)
        return value

    # Reschedule only the cloned controller's actual timer at the selected await.
    # No dependence on how long local fixture setup, disk I/O or measurement takes.
    state.namespace["asyncio"] = SimpleNamespace(**{**vars(asyncio), "timeout": timeout})

    async def reply(_request):
        if state.events[-1] == boundary:
            reached.append(boundary)
            timers[0].reschedule(asyncio.get_running_loop().time() + 0.01)
            await asyncio.sleep(1)
        return httpx.Response(200, stream=Stream([attestation()]))

    _, _, requests = install_client(reply)
    # 3.12 preserves the CancelledError subclass; 3.13 wraps it in TimeoutError.
    with pytest.raises(
        (ValueError, TimeoutError, publisher.CalibrationCalendarPublicationCancelled)
    ) as raised:
        await execute(state, timeout_seconds=60)
    assert reached == [boundary] and timers[0].expired()
    failure = raised.value.__cause__ if isinstance(raised.value, TimeoutError) else raised.value
    if isinstance(failure, publisher.CalibrationCalendarPublicationCancelled):
        root = state.registration_output if boundary == "registration" else state.measurement_output
        retained = json.loads((root / "publication.json").read_text(encoding="utf-8"))
        assert failure.publication_may_have_occurred is True
        assert failure.publication_sha256 == retained["publication_sha256"]
    assert len(requests) == (1 if boundary == "registration" else 2)
    assert not (state.output / "measurement.json").exists()
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("original", ["preflight", "native"])
async def test_original_production_gates_still_refuse_protocol_standins(
    controller_state, install_client, original
):
    state = controller_state(
        original_native=original == "native", original_preflight=original == "preflight"
    )
    _, _, requests = install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError):
        await execute(state)
    assert len(requests) == 1 and not state.measurement_output.exists()
    assert not (state.output / "measurement.json").exists()
    assert_disposed(state)


@pytest.mark.asyncio
async def test_constructed_or_serialized_handles_cannot_select_controller_progress():
    with pytest.raises(TypeError):
        controller._CalendarRecording()
    forged = object.__new__(controller._CalendarRecording)
    with pytest.raises(TypeError):
        pickle.dumps(forged)
    with pytest.raises(ValueError, match="absent or closed"):
        controller._require_calendar_recording(forged)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "module,name",
    [
        ("publisher_module", "prepare_calibration_registration_calendar"),
        ("publisher_module", "prepare_calibration_measurement_calendar"),
        ("publisher_module", "load_calibration_calendar_publication"),
        ("measured_module", "registered_calibration_measurement_scope"),
        ("measured_module", "load_registered_calibration_measurement"),
        ("measured_module", "_retain_file"),
        ("measured_module", "_require_files"),
    ],
)
async def test_replaced_producer_is_not_a_controller_callback(controller_state, module, name):
    state = controller_state()
    setattr(getattr(state, module), name, lambda **_: pytest.fail("replacement invoked"))
    with pytest.raises(ValueError, match="original producer"):
        await execute(state)
    assert not state.events and not state.registration_output.exists()
    assert all(secret.cleared for secret in state.secrets)


@pytest.mark.asyncio
async def test_descriptor_pins_and_complete_original_requests_are_retained_before_each_post(
    controller_state, install_client
):
    state = controller_state()

    def reply(request):
        root = (
            state.registration_output
            if state.events[-1] == "registration"
            else state.measurement_output
        )
        data = json.loads((root / "publication.json").read_bytes())
        started = json.loads((root / "calendar/001.json").read_bytes())
        assert started["kind"] == "POST_STARTED"
        assert data["preparation"] == started["preparation"]
        assert request.content.hex() == data["preparation"]["commitment_hex"]
        assert (root / "subject.json").is_file()
        return httpx.Response(200, stream=Stream([attestation()]))

    install_client(reply)
    await execute(state)
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["pending", "opaque"])
async def test_calendar_replay_never_promotes_pending_or_opaque_claims_to_authority(
    controller_state, install_client, kind
):
    state = controller_state()
    body = (
        attestation(PENDING, blob(b"https://untrusted-pending.invalid"))
        if kind == "pending"
        else attestation(b"opaque!!", b"untrusted metadata")
    )
    _, _, requests = install_client(lambda _: httpx.Response(200, stream=Stream([body])))
    result = await execute(state)
    assert [request.method for request in requests] == ["POST", "POST"]
    assert all(request.url.host == "calendar.invalid" for request in requests)
    for observation in (result.registration, result.measurement_publication):
        assert observation.calendar.events[-1].kind == "POST_REPLAYED"
        assert observation.binding.external_publication_verified is False
        assert observation.binding.pre_dispatch_anchoring_verified is False
        assert observation.binding.provider_call_authorized is False
        assert observation.binding.model_qualification_authorized is False
    assert result.measurement.receipt.release_authorized is False
    assert_disposed(state)


@pytest.mark.asyncio
async def test_another_task_cannot_borrow_even_the_live_controller_handle(
    controller_state, install_client
):
    state = controller_state()
    refusals = []

    async def reply(_request):
        async def borrow():
            with pytest.raises(ValueError, match="another task or process"):
                state.require_recording(state.key)
            refusals.append(True)

        await asyncio.create_task(borrow())
        return httpx.Response(200, stream=Stream([attestation()]))

    install_client(reply)
    await execute(state)
    assert refusals == [True, True]
    assert_disposed(state)


@pytest.mark.asyncio
async def test_changed_process_identity_refuses_before_any_preflight(
    controller_state, install_client
):
    state = controller_state()

    def reply(_request):
        state.namespace["os"] = SimpleNamespace(**{**vars(os), "getpid": lambda: os.getpid() + 1})
        return httpx.Response(200, stream=Stream([attestation()]))

    _, _, requests = install_client(reply)
    with pytest.raises(ValueError, match="another task or process"):
        await execute(state)
    assert len(requests) == 1 and "preflight-0" not in state.events
    assert_disposed(state)


@pytest.mark.asyncio
async def test_original_controller_phases_cannot_be_reentered_or_repeated(
    controller_state, install_client
):
    state = controller_state()
    checked = []

    async def reply(_request):
        if state.events[-1] == "measurement":
            with pytest.raises(ValueError, match="preflight-free registration"):
                await state.record_registration(state.key, state.journal)
            with pytest.raises(ValueError, match="complete original live measurement"):
                await state.record_measurement(state.key, state.live_measurement)
            checked.append(True)
        return httpx.Response(200, stream=Stream([attestation()]))

    _, _, requests = install_client(reply)
    await execute(state)
    assert checked == [True] and len(requests) == 2
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["registration", "measurement"])
async def test_synchronous_late_exchange_is_rejected_at_the_exact_phase_boundary(
    controller_state, install_client, boundary
):
    state = controller_state()
    now, reached = [0.0], []
    state.namespace["monotonic"] = lambda: now[0]

    def reply(_request):
        if state.events[-1] == boundary:
            reached.append(boundary)
            now[0] = 61.0
        return httpx.Response(200, stream=Stream([attestation()]))

    _, _, requests = install_client(reply)
    with pytest.raises(ValueError, match="overall deadline expired"):
        await execute(state, timeout_seconds=60)
    assert reached == [boundary]
    assert len(requests) == (1 if boundary == "registration" else 2)
    assert not (state.output / "measurement.json").exists()
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("refused", [False, True])
async def test_missing_slots_still_retain_every_available_original_preflight(
    controller_state, install_client, refused
):
    state = controller_state(3)
    if refused:
        state.fail_preflight = 0
    _, _, requests = install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError, match="missing or refused"):
        await execute(state, launches=state.launches[:2], operator_secrets=state.secrets[:2])
    final = read_journal(state.root)[-1]
    assert [slot.state for slot in final.slots] == [
        "REFUSED" if refused else "READY",
        "READY",
        "MISSING",
    ]
    assert state.events == ["registration", "preflight-0", "preflight-1"]
    assert len(requests) == 1 and final.disposition == "FAILED"
    assert not state.runner_live and len(state.ledger.snapshot().entries) == 1
    assert all(secret.cleared for secret in state.secrets[:2])
    assert not state.secrets[2].cleared
    with pytest.raises(ValueError, match="absent or closed"):
        state.require_recording(state.key)


@pytest.mark.asyncio
async def test_launch_change_during_registration_never_reaches_original_preflight(
    controller_state, install_client
):
    state = controller_state()

    def reply(_request):
        state.launches[0].config.label = "synthetic-changed-after-declaration"
        return httpx.Response(200, stream=Stream([attestation()]))

    _, _, requests = install_client(reply)
    with pytest.raises(ValueError, match="bindings changed during publication"):
        await execute(state)
    assert state.events == ["registration"] and len(requests) == 1
    assert read_journal(state.root)[-1].disposition == "FAILED"
    assert_disposed(state)
