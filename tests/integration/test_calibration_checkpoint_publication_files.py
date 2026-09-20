"""Private synthetic checkpoint files and bounded fresh processes; no public contact."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest

import mmaudit.orchestration.calibration_calendar_publication as legacy
import mmaudit.orchestration.calibration_checkpoint_publication as publisher
import mmaudit.orchestration.opentimestamps_calendar_journal as journal
import mmaudit.release_io as release_io
from tests.unit.test_calibration_checkpoint_publication import (
    population_state,
    prepare_measurement,
    prepare_registration,
    read,
    recover,
    registration_inputs,
)
from tests.unit.test_opentimestamps_calendar import attestation
from tests.unit.test_opentimestamps_calendar_journal import reseal
from tests.unit.test_opentimestamps_calendar_transport import Stream
from tests.unit.test_opentimestamps_calendar_transport import install_client as install_client
from tests.unit.test_registered_calibration_measurement import (
    measurement_protocol as measurement_protocol,
)

ROOT = Path(__file__).resolve().parents[2]
CHILD = r"""
import asyncio, json, sys
from pathlib import Path
from mmaudit.orchestration import calibration_checkpoint_publication as publisher
from mmaudit.orchestration import opentimestamps_calendar_transport as transport
from mmaudit.models.opentimestamps_calendar import replay_opentimestamps_calendar_response
mode, root, pin = sys.argv[1:]
requests = []
async def exchange(*, origin, request, timeout_seconds):
    assert origin == 'https://calendar.invalid' and request.method == 'GET'
    requests.append(request.method)
    body = bytes.fromhex('000588960d73d719010164')
    return transport.CalendarExchangeObservation(origin, request, 200, body,
        replay_opentimestamps_calendar_response(request, status_code=200, body=body))
transport._exchange = exchange
try:
    if mode == 'read':
        result = publisher.load_calibration_checkpoint_publication(
            output_root=Path(root), expected_publication_sha256=pin)
    else:
        result = asyncio.run(publisher.recover_calibration_checkpoint_publication(
            output_root=Path(root), expected_publication_sha256=pin, allow_calendar_contact=True))
except ValueError as failure:
    print(json.dumps({'refused': str(failure)}))
    sys.exit(21)
assert not hasattr(result, 'verification')
assert result.binding.external_publication_verified is False
assert result.checkpoint.serialized_authority is False
print(json.dumps({'checkpoint': result.checkpoint.subject_sha256,
    'kinds': [event.kind for event in result.calendar.events], 'requests': requests}))
"""


def child(mode, root, pin):
    return subprocess.run(
        [sys.executable, "-c", CHILD, mode, str(root), pin],
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


def replace_same(path, tmp_path):
    replacement = tmp_path / "synthetic-replacement"
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(0o600)
    replacement.replace(path)


@pytest.mark.asyncio
async def test_fresh_process_recovers_exact_checkpoint_by_get_after_source_loss(
    tmp_path, install_client
):
    state = registration_inputs(tmp_path)
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with prepare_registration(state) as owner:
        pin = owner.binding.publication_sha256
        observed = await owner.submit(allow_calendar_contact=True)
        locked = child("read", state.output, pin)
        assert locked.returncode == 21 and "lock is busy" in locked.stdout
    state.root.rename(tmp_path / "unavailable-population")
    fresh = child("recover", state.output, pin)
    assert fresh.returncode == 0, fresh.stderr
    assert json.loads(fresh.stdout) == {
        "checkpoint": observed.checkpoint.subject_sha256,
        "kinds": ["PREPARED", "POST_STARTED", "POST_REPLAYED", "LOOKUP_STARTED", "LOOKUP_REPLAYED"],
        "requests": ["GET"],
    }
    assert {p.name for p in (state.output / "source/calendar").iterdir()} == {"000.json"}


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_checkpoint",
        "missing_source",
        "extra",
        "partial_checkpoint",
        "partial_descriptor",
        "whitespace",
        "duplicate_key",
        "oversized",
        "checkpoint_symlink",
        "checkpoint_hardlink",
        "descriptor_mode",
        "root_mode",
        "calendar_symlink",
        "wrong_subject",
        "wrong_preparation",
        "source_dispatched",
        "partial_tail",
    ],
)
def test_corrupt_partial_or_rehashed_files_never_return_a_repaired_checkpoint(tmp_path, mutation):
    state = registration_inputs(tmp_path)
    with prepare_registration(state) as owner:
        pin = owner.binding.publication_sha256
    root = state.output
    envelope, descriptor = root / "checkpoint.json", root / "publication.json"
    if mutation == "missing_checkpoint":
        envelope.unlink()
    elif mutation == "missing_source":
        (root / "source").rename(tmp_path / "lost-source")
    elif mutation == "extra":
        (root / "unexpected").write_bytes(b"synthetic")
    elif mutation == "partial_checkpoint":
        envelope.write_bytes(b"{")
    elif mutation == "partial_descriptor":
        descriptor.write_bytes(b"{")
    elif mutation == "whitespace":
        descriptor.write_bytes(descriptor.read_bytes() + b"\n")
    elif mutation == "duplicate_key":
        descriptor.write_bytes(b'{"schema_version":"1.0",' + descriptor.read_bytes()[1:])
    elif mutation == "oversized":
        envelope.write_bytes(b"x" * (publisher.MAX_CALIBRATION_CHECKPOINT_SUBJECT_BYTES + 1))
    elif mutation == "checkpoint_symlink":
        target = tmp_path / "checkpoint-copy"
        envelope.rename(target)
        envelope.symlink_to(target)
    elif mutation == "checkpoint_hardlink":
        os.link(envelope, tmp_path / "extra-alias")
    elif mutation == "descriptor_mode":
        descriptor.chmod(0o640)
    elif mutation == "root_mode":
        root.chmod(0o750)
    elif mutation == "calendar_symlink":
        calendar = root / "calendar"
        target = tmp_path / "calendar-copy"
        calendar.rename(target)
        calendar.symlink_to(target, target_is_directory=True)
    elif mutation == "source_dispatched":
        (root / "source/calendar/001.json").write_bytes(b"{")
    elif mutation == "partial_tail":
        (root / "calendar/001.json").write_bytes(b"{")
    else:
        data = json.loads(descriptor.read_bytes())
        if mutation == "wrong_subject":
            data["registration_event_sha256"] = "f" * 64
        else:
            data["preparation"]["calendar_origin"] = "https://different.invalid"
            data["preparation"] = json.loads(reseal(data["preparation"], "preparation_sha256"))
        raw = reseal(data, "publication_sha256")
        descriptor.write_bytes(raw)
        pin = json.loads(raw)["publication_sha256"]
    names = {p.relative_to(root) for p in root.rglob("*")}
    with pytest.raises(ValueError):
        read(root, pin)
    assert {p.relative_to(root) for p in root.rglob("*")} == names


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target",
    [
        "population",
        "source/subject.json",
        "source/publication.json",
        "source/calendar/000.json",
        "checkpoint.json",
        "publication.json",
        "calendar/000.json",
        "root",
    ],
)
async def test_same_byte_replacement_across_await_refuses_original_custody(
    tmp_path, install_client, target
):
    state = registration_inputs(tmp_path)

    def mutate():
        if target == "root":
            state.output.rename(tmp_path / "displaced-checkpoint")
            state.output.mkdir(mode=0o700)
        else:
            path = state.root / "000.json" if target == "population" else state.output / target
            replace_same(path, tmp_path)

    clients, _, requests = install_client(
        lambda _: httpx.Response(200, stream=Stream([attestation()], on_chunk=mutate))
    )
    with (
        pytest.raises(legacy.CalibrationCalendarPublicationError),
        prepare_registration(state) as owner,
    ):
        await owner.submit(allow_calendar_contact=True)
    assert len(requests) == 1 and all(c.is_closed for c in clients)


@pytest.mark.parametrize("target", ["checkpoint.json", "calendar/000.json"])
def test_original_creator_inode_cannot_be_reobserved_as_a_replacement(
    tmp_path, monkeypatch, target
):
    state = registration_inputs(tmp_path)
    original = publisher.write_json_evidence
    changed = False

    def write(**kwargs):
        nonlocal changed
        if (
            kwargs["relative_path"] == "publication.json"
            and kwargs["evidence_root"] == state.output
        ):
            replace_same(state.output / target, tmp_path)
            changed = True
        return original(**kwargs)

    monkeypatch.setattr(publisher, "write_json_evidence", write)
    with pytest.raises(ValueError), prepare_registration(state):
        pytest.fail("creator custody silently replaced by new observation")
    assert changed and not (state.output / "calendar/001.json").exists()


@pytest.mark.parametrize("target", ["checkpoint.json", "publication.json"])
def test_failed_fsync_cannot_yield_a_dispatchable_checkpoint(tmp_path, monkeypatch, target):
    state = registration_inputs(tmp_path)
    original = os.fsync

    def fail(fd):
        path = state.output / target
        if path.exists() and path.stat().st_ino == os.fstat(fd).st_ino:
            raise OSError("synthetic checkpoint fsync failure")
        original(fd)

    monkeypatch.setattr(release_io.os, "fsync", fail)
    with pytest.raises(ValueError), prepare_registration(state):
        pytest.fail("incomplete checkpoint descriptor admitted")
    assert not (state.output / "publication.json").exists()
    assert not (state.output / "calendar/001.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["replace_reply", "append_lookup"])
async def test_measurement_retains_the_complete_original_predecessor_calendar_history(
    measurement_protocol, install_client, tmp_path, mutation
):
    state = population_state(measurement_protocol)
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    async with state.scope(**state.args) as live:
        # Record an interrupted original attempt; recovery is GET-only and data-only.
        with journal._locked_journal(state.output / "calendar") as held:
            held.load(state.registration_binding.preparation.preparation_sha256)
            held.append("POST_STARTED", held.events[0].preparation)
        await recover(state.output, state.registration_binding.publication_sha256)
        with pytest.raises(ValueError), prepare_measurement(state, live):
            if mutation == "replace_reply":
                replace_same(state.output / "calendar/003.json", tmp_path)
            else:
                await recover(state.output, state.registration_binding.publication_sha256)
    assert state.closed and state.secret.cleared


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["publication.json", "calendar/002.json"])
async def test_existing_recovery_prefix_custody_survives_child_close(
    tmp_path, monkeypatch, install_client, target
):
    state = registration_inputs(tmp_path)
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with prepare_registration(state) as owner:
        pin = owner.binding.publication_sha256
        await owner.submit(allow_calendar_contact=True)
    original, changed = journal._locked_journal, False

    @contextmanager
    def locked(root, **kwargs):
        nonlocal changed
        with original(root, **kwargs) as held:
            yield held
        if root == state.output / "calendar" and len(held.events) == 5 and not changed:
            assert held.closed
            changed = True
            replace_same(state.output / target, tmp_path)

    monkeypatch.setattr(journal, "_locked_journal", locked)
    with pytest.raises(legacy.CalibrationCalendarPublicationError):
        await recover(state.output, pin)
    assert changed


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["checkpoint_close", "source_close", "recovery_close"])
async def test_new_outcome_custody_survives_every_enclosing_cleanup(
    tmp_path, monkeypatch, install_client, boundary
):
    state = registration_inputs(tmp_path)
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    original, changed = journal._locked_journal, False

    @contextmanager
    def locked(root, **kwargs):
        nonlocal changed
        with original(root, **kwargs) as held:
            yield held
        target_root = state.output / (
            "source/calendar" if boundary == "source_close" else "calendar"
        )
        outcome = state.output / (
            "calendar/004.json" if boundary == "recovery_close" else "calendar/002.json"
        )
        if root == target_root and outcome.exists() and not changed:
            assert held.closed
            changed = True
            replace_same(outcome, tmp_path)

    if boundary == "recovery_close":
        with prepare_registration(state) as owner:
            pin = owner.binding.publication_sha256
            await owner.submit(allow_calendar_contact=True)
        monkeypatch.setattr(journal, "_locked_journal", locked)
        with pytest.raises(legacy.CalibrationCalendarPublicationError):
            await recover(state.output, pin)
    else:
        monkeypatch.setattr(journal, "_locked_journal", locked)
        with pytest.raises(ValueError), prepare_registration(state) as owner:
            await owner.submit(allow_calendar_contact=True)
    assert changed


def test_checkpoint_output_cannot_overlap_original_population(tmp_path):
    state = registration_inputs(tmp_path)
    original = (state.root / "000.json").read_bytes()
    for target in (state.root, state.root / "checkpoint", state.root.parent):
        with (
            pytest.raises(ValueError, match="separate"),
            prepare_registration(state, output_root=target),
        ):
            pytest.fail("checkpoint output overlapped its original population")
    assert (state.root / "000.json").read_bytes() == original
