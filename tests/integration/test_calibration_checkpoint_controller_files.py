"""Real private checkpoint batch files and a disposable reader process, never a chain seal."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import httpx
import pytest

import mmaudit.orchestration.calibration_calendar_controller as controller
import mmaudit.orchestration.calibration_calendar_publication as legacy
import mmaudit.orchestration.calibration_checkpoint_publication as publisher
from tests.integration.test_calibration_calendar_controller_files import replace_same_bytes
from tests.unit.test_calibration_calendar_controller import assert_disposed, execute
from tests.unit.test_calibration_calendar_controller import controller_state as controller_state
from tests.unit.test_calibration_checkpoint_controller import set_tip
from tests.unit.test_calibration_population_journal import read_journal
from tests.unit.test_opentimestamps_calendar import attestation
from tests.unit.test_opentimestamps_calendar_transport import Stream
from tests.unit.test_opentimestamps_calendar_transport import install_client as install_client
from tests.unit.test_registered_calibration_measurement import (
    measurement_protocol as measurement_protocol,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changed", ["ledger", "population", "native_measurement", "native_receipt"]
)
async def test_final_checkpoint_readback_rechecks_original_native_files_population_and_ledger(
    controller_state, install_client, changed
):
    state = controller_state(checkpoint=True)
    set_tip(state)
    reached = []

    def mutate():
        assert not state.runner_live
        with pytest.raises(ValueError, match="absent or revoked"):
            state.require(state.proof, state.measured)
        reached.append(changed)
        if changed == "ledger":
            charge = state.ledger.reserve("synthetic-late-checkpoint-liability", Decimal("1"))
            state.ledger.reconcile(charge, None)
        else:
            replace_same_bytes(
                {
                    "population": state.root / "000.json",
                    "native_measurement": state.output / "calibration.json",
                    "native_receipt": state.output / "measurement.json",
                }[changed]
            )

    state.on_readback = mutate
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError):
        await execute(state)
    assert reached == [changed]
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stage,phase,relative",
    [
        ("preflight", "registration", "checkpoint.json"),
        ("preflight", "registration", "calendar/002.json"),
        ("runner", "registration", "source/subject.json"),
        ("runner", "registration", "publication.json"),
        ("cleanup", "registration", "source/calendar/000.json"),
        ("cleanup", "measurement", "checkpoint.json"),
        ("cleanup", "measurement", "calendar/001.json"),
        ("cleanup", "measurement", "calendar/002.json"),
    ],
)
async def test_original_checkpoint_phase_inodes_survive_preflight_runner_and_cleanup(
    controller_state, install_client, stage, phase, relative
):
    state = controller_state(3, checkpoint=True)
    root = state.registration_output if phase == "registration" else state.measurement_output
    reached = []

    def mutate(index):
        if index == (2 if stage == "cleanup" else 0):
            replace_same_bytes(root / relative)
            reached.append(index)

    setattr(state, "on_" + stage, mutate)
    _, _, requests = install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError):
        await execute(state)
    assert len(reached) == 1 and read_journal(state.root)[-1].disposition == "FAILED"
    if stage == "preflight":
        assert "preflight-1" not in state.events and "runner-0" not in state.events
    if stage == "runner":
        assert "runner-1" not in state.events
    assert len(requests) == (2 if stage == "cleanup" else 1)
    assert not (state.output / "measurement.json").exists()
    assert_disposed(state)


@pytest.mark.asyncio
async def test_fresh_process_reads_both_checkpoint_phases_without_native_or_controller_authority(
    controller_state, install_client
):
    state = controller_state(checkpoint=True)
    tip = set_tip(state)
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    result = await execute(state)
    reader = """
import json,sys
from pathlib import Path
from mmaudit.orchestration import calibration_calendar_controller as controller
from mmaudit.orchestration.calibration_checkpoint_publication import load_calibration_checkpoint_publication
from mmaudit.orchestration.authenticated_calibration_measurement import load_registered_calibration_measurement
first=load_calibration_checkpoint_publication(output_root=Path(sys.argv[1]), expected_publication_sha256=sys.argv[2])
last=load_calibration_checkpoint_publication(output_root=Path(sys.argv[3]), expected_publication_sha256=sys.argv[4])
native=load_registered_calibration_measurement(evidence_root=Path(sys.argv[5]), output_root=Path(sys.argv[6]), expected_registration_sha256=first.binding.registration_event_sha256)
assert last.subject.calibration==native.calibration and not hasattr(native,'verification')
assert last.checkpoint.transparency_proof.previous_checkpoint==first.checkpoint.transparency_proof.checkpoint
assert last.checkpoint.registration_checkpoint_subject_sha256==first.checkpoint.subject_sha256
assert first.binding.external_publication_verified is last.binding.external_publication_verified is False
try:
 controller._require_calendar_recording(object.__new__(controller._CalendarRecording))
except ValueError:
 pass
else:
 raise AssertionError('checkpoint files recreated an owned controller')
print(json.dumps({'initial_tip':first.checkpoint.transparency_proof.previous_checkpoint.checkpoint_sha256,
    'measurement':native.receipt.measurement_sha256,'authority':False}))
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            reader,
            str(state.registration_output),
            result.registration.binding.publication_sha256,
            str(state.measurement_output),
            result.measurement_publication.binding.publication_sha256,
            str(state.root),
            str(state.output),
        ],
        cwd=ROOT,
        env={
            "PATH": os.defpath,
            "PYTHONPATH": str(ROOT / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "MMAUDIT_RUN_REAL_PROVIDER_TESTS": "0",
            "MMAUDIT_SECRETS_ENV_FILE": "",
        },
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "initial_tip": tip.checkpoint.checkpoint_sha256,
        "measurement": result.measurement.receipt.measurement_sha256,
        "authority": False,
    }
    assert_disposed(state)


@pytest.mark.asyncio
async def test_failed_checkpoint_registration_only_allows_get_data_recovery_not_batch_resume(
    controller_state, install_client
):
    state = controller_state(checkpoint=True)
    set_tip(state)
    clients, _, requests = install_client(
        lambda request: httpx.Response(
            503 if request.method == "POST" else 200, stream=Stream([attestation()])
        )
    )
    with pytest.raises(legacy.CalibrationCalendarPublicationError) as failure:
        await execute(state)
    result = await publisher.recover_calibration_checkpoint_publication(
        output_root=state.registration_output,
        expected_publication_sha256=failure.value.publication_sha256,
        allow_calendar_contact=True,
    )
    assert result.checkpoint.population_subject_sha256 == result.subject.subject_sha256
    assert result.calendar.events[-1].kind == "LOOKUP_REPLAYED"
    assert result.binding.external_publication_verified is False
    assert [r.method for r in requests] == ["POST", "GET"]
    with pytest.raises(ValueError):
        await execute(state)
    assert [r.method for r in requests] == ["POST", "GET"]
    assert not any(event.startswith(("preflight", "runner")) for event in state.events)
    assert len(state.ledger.snapshot().entries) == 1 and all(c.is_closed for c in clients)
    assert_disposed(state)


@pytest.mark.asyncio
async def test_concurrent_checkpoint_get_history_cannot_join_an_active_batch(
    controller_state, install_client
):
    state = controller_state(checkpoint=True)
    recovered = []

    async def reply(request):
        if state.events[-1] == "measurement" and request.method == "POST":
            descriptor = json.loads((state.registration_output / "publication.json").read_bytes())
            recovered.append(
                await publisher.recover_calibration_checkpoint_publication(
                    output_root=state.registration_output,
                    expected_publication_sha256=descriptor["publication_sha256"],
                    allow_calendar_contact=True,
                )
            )
        return httpx.Response(200, stream=Stream([attestation()]))

    install_client(reply)
    with pytest.raises(ValueError):
        await execute(state)
    assert len(recovered) == 1
    assert not (state.output / "measurement.json").exists()
    assert_disposed(state)


@pytest.mark.asyncio
async def test_checkpoint_measurement_outcome_replacement_after_retention_is_refused(
    controller_state, install_client, monkeypatch
):
    state = controller_state(checkpoint=True)
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    original = controller._RecordedCheckpointPublication.require_unchanged
    changed = []

    def require(self):
        original(self)
        if self.observation.checkpoint.phase == "MEASURED_POPULATION" and not changed:
            # A replacement cannot become the original retained phase outcome.
            changed.append(True)
            replace_same_bytes(state.measurement_output / "calendar/002.json")

    monkeypatch.setattr(controller._RecordedCheckpointPublication, "require_unchanged", require)
    with pytest.raises(ValueError):
        await execute(state)
    assert changed
    assert not (state.output / "measurement.json").exists()
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("root", ["population", "native_output", "other_publication"])
async def test_checkpoint_output_overlap_cannot_mutate_original_inputs(
    controller_state, install_client, root
):
    state = controller_state(checkpoint=True)
    target = {
        "population": state.root / "nested",
        "native_output": state.output,
        "other_publication": state.measurement_output,
    }[root]
    _, _, requests = install_client(lambda _: pytest.fail("overlap dispatched"))
    with pytest.raises(ValueError, match="separate"):
        await execute(state, registration_publication_root=target)
    assert not requests and not state.events
    assert not tuple(state.root.iterdir()) and not tuple(state.output.iterdir())
    assert_disposed(state)
