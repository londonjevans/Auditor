"""Real controller evidence custody and fresh-process readers over synthetic local data."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import httpx
import pytest

import mmaudit.orchestration.calibration_calendar_publication as publisher
from tests.unit.test_calibration_calendar_controller import assert_disposed, execute
from tests.unit.test_calibration_calendar_controller import controller_state as controller_state
from tests.unit.test_calibration_population_journal import read_journal
from tests.unit.test_opentimestamps_calendar import attestation
from tests.unit.test_opentimestamps_calendar_transport import Stream
from tests.unit.test_opentimestamps_calendar_transport import install_client as install_client
from tests.unit.test_registered_calibration_measurement import (
    measurement_protocol as measurement_protocol,
)

ROOT = Path(__file__).resolve().parents[2]


def replace_same_bytes(path):
    previous = path.stat().st_ino
    raw = path.read_bytes()
    displaced = path.with_name(path.name + ".old")
    path.rename(displaced)
    path.write_bytes(raw)
    path.chmod(0o600)
    assert path.stat().st_ino != previous
    # Remove only the synthetic displaced alias so membership alone cannot catch it.
    displaced.unlink()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changed", ["ledger", "population", "native_measurement", "native_receipt"]
)
async def test_final_readback_cannot_accept_late_original_source_or_ledger_changes(
    controller_state, install_client, changed
):
    state = controller_state()
    reached = []

    def mutate():
        assert not state.runner_live
        with pytest.raises(ValueError, match="absent or revoked"):
            state.require(state.proof, state.measured)
        reached.append(changed)
        if changed == "ledger":
            charge = state.ledger.reserve("synthetic-late-liability", Decimal("1"))
            state.ledger.reconcile(charge, None)
        else:
            path = {
                "population": state.root / "000.json",
                "native_measurement": state.output / "calibration.json",
                "native_receipt": state.output / "measurement.json",
            }[changed]
            replace_same_bytes(path)

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
        ("preflight", "registration", "calendar/001.json"),
        ("preflight", "registration", "calendar/002.json"),
        ("runner", "registration", "publication.json"),
        ("runner", "registration", "calendar/002.json"),
        ("cleanup", "registration", "subject.json"),
        ("cleanup", "measurement", "calendar/001.json"),
        ("cleanup", "measurement", "calendar/002.json"),
    ],
)
async def test_same_byte_phase_replacement_stops_next_work_and_refuses_final_completion(
    controller_state, install_client, stage, phase, relative
):
    state = controller_state(3)
    root = state.registration_output if phase == "registration" else state.measurement_output
    reached = []

    def mutate(index):
        if index == (2 if stage == "cleanup" else 0):
            reached.append(index)
            replace_same_bytes(root / relative)

    setattr(state, "on_" + stage, mutate)
    _, _, requests = install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError):
        await execute(state)
    assert len(reached) == 1
    assert read_journal(state.root)[-1].disposition == "FAILED"
    assert not (state.output / "measurement.json").exists()
    if stage == "preflight":
        assert "preflight-1" not in state.events and "runner-0" not in state.events
    if stage == "runner":
        assert "runner-1" not in state.events
    assert len(requests) == (2 if stage == "cleanup" else 1)
    assert_disposed(state)


@pytest.mark.asyncio
async def test_fresh_process_reads_completed_data_but_cannot_recreate_controller_or_native_custody(
    controller_state, install_client
):
    state = controller_state()
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    result = await execute(state)
    reader = """
import json,sys
from pathlib import Path
from mmaudit.orchestration import calibration_calendar_controller as c
from mmaudit.orchestration import calibration_calendar_publication as p
from mmaudit.orchestration.authenticated_calibration_measurement import load_registered_calibration_measurement
first=p.load_calibration_calendar_publication(output_root=Path(sys.argv[1]), expected_publication_sha256=sys.argv[2])
last=p.load_calibration_calendar_publication(output_root=Path(sys.argv[3]), expected_publication_sha256=sys.argv[4])
data=load_registered_calibration_measurement(evidence_root=Path(sys.argv[5]), output_root=Path(sys.argv[6]), expected_registration_sha256=first.binding.registration_event_sha256)
assert last.subject.calibration==data.calibration and not hasattr(data,'verification')
assert first.binding.external_publication_verified is last.binding.external_publication_verified is False
try:
 c._require_calendar_recording(object.__new__(c._CalendarRecording))
except ValueError:
 pass
else:
 raise AssertionError('data reader recreated controller')
print(json.dumps({'registration':first.subject.subject_sha256,'measurement':data.receipt.measurement_sha256,'authority':False}))
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
        "registration": result.registration.subject.subject_sha256,
        "measurement": result.measurement.receipt.measurement_sha256,
        "authority": False,
    }
    assert_disposed(state)


@pytest.mark.asyncio
async def test_failed_registration_retains_original_pin_and_allows_only_data_lookup(
    controller_state, install_client
):
    state = controller_state()

    def respond(request):
        return httpx.Response(
            503 if request.method == "POST" else 200, stream=Stream([attestation()])
        )

    clients, _, requests = install_client(respond)
    with pytest.raises(publisher.CalibrationCalendarPublicationError) as failure:
        await execute(state)
    data = await publisher.recover_calibration_calendar_publication(
        output_root=state.registration_output,
        expected_publication_sha256=failure.value.publication_sha256,
        allow_calendar_contact=True,
    )
    assert [request.method for request in requests] == ["POST", "GET"]
    assert data.subject.population_events[0].kind == "REGISTERED"
    assert data.binding.external_publication_verified is False
    assert data.calendar.events[-1].kind == "LOOKUP_REPLAYED"
    assert all(client.is_closed for client in clients)
    # Reopening original files cannot make the failed batch or its POST eligible again.
    with pytest.raises(ValueError):
        await execute(state)
    assert [request.method for request in requests] == ["POST", "GET"]
    assert not any(event.startswith(("preflight", "runner")) for event in state.events)
    assert len(state.ledger.snapshot().entries) == 1
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("root", ["population", "native_output", "other_publication"])
async def test_overlapping_publication_roots_refuse_before_any_original_file_changes(
    controller_state, install_client, root
):
    state = controller_state()
    changed = {
        "population": state.root / "nested",
        "native_output": state.output,
        "other_publication": state.measurement_output,
    }[root]
    _, _, requests = install_client(lambda _: pytest.fail("overlap dispatched"))
    with pytest.raises(ValueError, match="separate"):
        await execute(state, registration_publication_root=changed)
    assert not requests and not state.events
    assert not tuple(state.root.iterdir()) and not tuple(state.output.iterdir())
    assert_disposed(state)
