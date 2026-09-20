"""Completion custody over real disposable files; mock calendar and no external authority."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from mmaudit.operator_secrets import OperatorSecrets
from tests.integration.test_calibration_calendar_controller_files import replace_same_bytes
from tests.unit.test_calibration_calendar_controller import assert_disposed
from tests.unit.test_calibration_calendar_controller import controller_state as controller_state
from tests.unit.test_calibration_completion import completion_state as completion_state
from tests.unit.test_opentimestamps_calendar import attestation
from tests.unit.test_opentimestamps_calendar_transport import Stream
from tests.unit.test_opentimestamps_calendar_transport import install_client as install_client
from tests.unit.test_registered_calibration_measurement import (
    measurement_protocol as measurement_protocol,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("cleanup", ["timer", "secrets"])
async def test_final_cleanup_cannot_replace_original_evidence_after_consumer_exit(
    completion_state, install_client, monkeypatch, cleanup
):
    state = completion_state()
    state.consumer_exited = False
    changed = []

    def mutate():
        if state.consumer_exited and not changed:
            replace_same_bytes(state.measurement_output / "checkpoint.json")
            changed.append(cleanup)

    if cleanup == "timer":

        class Timer:
            def __init__(self, seconds):
                self.original = asyncio.timeout(seconds)

            async def __aenter__(self):
                return await self.original.__aenter__()

            async def __aexit__(self, *exception):
                result = await self.original.__aexit__(*exception)
                mutate()
                return result

            def expired(self):
                return self.original.expired()

        state.namespace["asyncio"] = SimpleNamespace(**{**vars(asyncio), "timeout": Timer})
    else:
        original_clear = OperatorSecrets.clear

        def clear(secret):
            original_clear(secret)
            mutate()

        monkeypatch.setattr(OperatorSecrets, "clear", clear)

    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError):
        async with state.completion_scope(**state.args) as handle:
            state.observe_completion(handle)
            state.consumer_exited = True
    assert changed == [cleanup]
    with pytest.raises(ValueError, match="absent or closed"):
        state.observe_completion(handle)
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "root,relative",
    [
        ("registration_output", "checkpoint.json"),
        ("registration_output", "calendar/002.json"),
        ("measurement_output", "publication.json"),
        ("measurement_output", "source/subject.json"),
        ("measurement_output", "calendar/001.json"),
        ("output", "calibration.json"),
        ("output", "measurement.json"),
        ("root", "000.json"),
    ],
)
async def test_consumer_cannot_return_success_after_same_byte_original_file_replacement(
    completion_state, install_client, root, relative
):
    state = completion_state()
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError):
        async with state.completion_scope(**state.args) as handle:
            state.observe_completion(handle)
            await asyncio.sleep(0)
            replace_same_bytes(getattr(state, root) / relative)
    with pytest.raises(ValueError, match="absent or closed"):
        state.observe_completion(handle)
    assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("actual", [None, Decimal("0.01")])
async def test_terminal_completion_cannot_absorb_later_known_or_unknown_ledger_costs(
    completion_state, install_client, actual
):
    state = completion_state()
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError, match="terminal population or ledger changed"):
        async with state.completion_scope(**state.args) as handle:
            state.observe_completion(handle)
            charge = state.ledger.reserve("synthetic-after-completion", Decimal("1"))
            state.ledger.commit_for_transport(charge)
            state.ledger.reconcile(charge, actual)
    with pytest.raises(ValueError, match="absent or closed"):
        state.observe_completion(handle)
    assert_disposed(state)


@pytest.mark.asyncio
async def test_fresh_process_cannot_reenroll_completion_from_original_terminal_files(
    completion_state, install_client
):
    state = completion_state()
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    async with state.completion_scope(**state.args) as handle:
        result = state.observe_completion(handle)
    reader = """
import json,sys
from pathlib import Path
from mmaudit.orchestration.authenticated_calibration_measurement import load_registered_calibration_measurement
from mmaudit.orchestration.calibration_calendar_controller import OwnedCheckpointCalibrationCompletion, observe_checkpoint_calibration_completion
from mmaudit.orchestration.calibration_checkpoint_publication import load_calibration_checkpoint_publication
phase=load_calibration_checkpoint_publication(output_root=Path(sys.argv[1]),expected_publication_sha256=sys.argv[2])
measurement=load_registered_calibration_measurement(evidence_root=Path(sys.argv[3]),output_root=Path(sys.argv[4]),expected_registration_sha256=sys.argv[5])
assert phase.subject.calibration==measurement.calibration
assert phase.binding.external_publication_verified is False
assert not hasattr(measurement,'verification')
for value in (measurement,phase,object.__new__(OwnedCheckpointCalibrationCompletion)):
 try:
  observe_checkpoint_calibration_completion(value)
 except ValueError as exc:
  assert 'absent or closed' in str(exc)
 else:
  raise AssertionError('readback reconstructed original completion')
print(json.dumps({'receipt':measurement.receipt.measurement_sha256,'completion':False}))
"""
    root = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            reader,
            str(state.measurement_output),
            result.measurement_publication.binding.publication_sha256,
            str(state.root),
            str(state.output),
            result.measurement.receipt.registration_sha256,
        ],
        cwd=root,
        env={
            "PATH": os.defpath,
            "PYTHONPATH": str(root / "src"),
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
        "receipt": result.measurement.receipt.measurement_sha256,
        "completion": False,
    }
    assert_disposed(state)
