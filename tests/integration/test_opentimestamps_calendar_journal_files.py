"""Disposable private files and fresh processes; no live calendar or external authority."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

import mmaudit.orchestration.opentimestamps_calendar_journal as journal
import mmaudit.release_io as release_io
from mmaudit.reporting.json_report import stable_json
from tests.unit.test_calibration_publication import publication_data as publication_data
from tests.unit.test_opentimestamps_calendar import attestation
from tests.unit.test_opentimestamps_calendar_journal import (
    load,
    missing_outcome,
    prepare,
    recover,
    reseal,
)
from tests.unit.test_opentimestamps_calendar_transport import Stream
from tests.unit.test_opentimestamps_calendar_transport import install_client as install_client

ROOT = Path(__file__).resolve().parents[2]
CHILD = r"""
import asyncio, json, os, sys
from pathlib import Path
from mmaudit.orchestration import opentimestamps_calendar_journal as journal
from mmaudit.orchestration import opentimestamps_calendar_transport as transport
from mmaudit.orchestration.calibration_publication import CalibrationPublicationSubject
from mmaudit.models.opentimestamps_calendar import replay_opentimestamps_calendar_response
mode, root_arg, supplied = sys.argv[1:]
root = Path(root_arg)
if mode in {"locked", "read"}:
    try:
        data = journal.load_calibration_calendar_journal(evidence_root=root, expected_preparation_sha256=supplied)
    except ValueError as failure:
        print(json.dumps({"refused": str(failure)}), flush=True)
        sys.exit(21)
    print(json.dumps({"kinds": [e.kind for e in data.events]}), flush=True)
    sys.exit(0)
subject = CalibrationPublicationSubject.model_validate_json(Path(supplied).read_bytes())
original_write = journal.write_json_evidence
def write(**kwargs):
    if kwargs["relative_path"] == "002.json":
        if mode == "partial_outcome":
            fd = os.open(root / "002.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, b"{")
            os.fsync(fd)
            os._exit(19)
        if mode == "after_response":
            os._exit(19)
    return original_write(**kwargs)
journal.write_json_evidence = write
async def exchange(*, origin, request, timeout_seconds):
    assert request.method == "POST" and request.relative_path == "digest"
    print(json.dumps({"intent_seen": (root / "001.json").is_file()}), flush=True)
    if mode == "after_intent":
        os._exit(19)
    body = bytes.fromhex("0083dfe30d2ef90c8e0164")
    return transport.CalendarExchangeObservation(origin, request, 200, body,
        replay_opentimestamps_calendar_response(request, status_code=200, body=body))
transport._exchange = exchange
async def run():
    with journal.prepare_calibration_calendar_journal(evidence_root=root, subject=subject,
            calendar_origin="https://calendar.invalid") as owner:
        print(json.dumps({"pin": owner.preparation.preparation_sha256}), flush=True)
        if mode == "after_preparation":
            os._exit(19)
        await owner.submit(allow_calendar_contact=True)
asyncio.run(run())
raise AssertionError("crash fixture did not stop at its selected local boundary")
"""


def child(mode, root, argument):
    return subprocess.run(
        [sys.executable, "-c", CHILD, mode, str(root), str(argument)],
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


def test_real_process_exclusion_and_release_prevent_concurrent_journal_access(
    tmp_path, publication_data
):
    root = tmp_path / "journal"
    with prepare(root, publication_data.registration) as owner:
        pin = owner.preparation.preparation_sha256
        result = child("locked", root, pin)
        assert result.returncode == 21, result.stderr
        assert "lock is busy" in json.loads(result.stdout)["refused"]
        with pytest.raises(ValueError, match="lock is busy"):
            load(root, pin)
    result = child("read", root, pin)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["kinds"] == ["PREPARED"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "boundary",
    [
        "after_preparation",
        "after_intent",
        "after_response",
        "partial_outcome",
    ],
)
async def test_fresh_process_loss_retains_context_without_post_replay_or_silent_tail_repair(
    tmp_path, publication_data, install_client, boundary
):
    root, subject = tmp_path / "journal", publication_data.registration
    supplied = tmp_path / "synthetic-subject.json"
    supplied.write_text(stable_json(subject.model_dump(mode="json")))
    result = child(boundary, root, supplied)
    assert result.returncode == 19, result.stderr
    messages = [json.loads(line) for line in result.stdout.splitlines()]
    pin = messages[0]["pin"]
    if boundary != "after_preparation":
        assert messages[1] == {"intent_seen": True}
    clients, _, requests = install_client(
        lambda _: httpx.Response(200, stream=Stream([attestation()]))
    )
    if boundary in {"after_preparation", "partial_outcome"}:
        with pytest.raises(ValueError):
            await recover(root, subject, pin)
        assert not requests
        if boundary == "partial_outcome":
            assert (root / "002.json").read_bytes() == b"{"
    else:
        before = load(root, pin)
        assert [e.kind for e in before.events] == ["PREPARED", "POST_STARTED"]
        recovered = await recover(root, subject, pin)
        assert recovered.events[:2] == before.events
        assert recovered.events[-1].kind == "LOOKUP_REPLAYED"
        assert len(requests) == 1 and requests[0].method == "GET"
        assert all(c.is_closed for c in clients)
        fresh = child("read", root, pin)
        assert fresh.returncode == 0, fresh.stderr
        assert json.loads(fresh.stdout)["kinds"][-1] == "LOOKUP_REPLAYED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "truncated",
        "whitespace",
        "extra",
        "missing",
        "oversized",
        "symlink",
        "hardlink",
        "file_mode",
        "directory_mode",
        "rehash_transition",
        "rehash_context",
        "overflow_count",
    ],
)
async def test_disk_history_mutation_is_inconclusive_and_never_repaired_or_contacted(
    tmp_path, publication_data, install_client, mutation
):
    root, subject = tmp_path / "journal", publication_data.registration
    pin = missing_outcome(root, subject)
    path = root / "001.json"
    raw = path.read_bytes()
    if mutation == "truncated":
        path.write_bytes(raw[:-1])
    elif mutation == "whitespace":
        path.write_bytes(raw + b"\n")
    elif mutation == "extra":
        (root / "extra").write_bytes(b"synthetic")
    elif mutation == "missing":
        (root / "000.json").unlink()
    elif mutation == "oversized":
        path.write_bytes(b"x" * (journal.MAX_CALENDAR_JOURNAL_EVENT_BYTES + 1))
    elif mutation == "symlink":
        original = tmp_path / "original-event"
        path.rename(original)
        path.symlink_to(original)
    elif mutation == "hardlink":
        os.link(path, tmp_path / "extra-hardlink")
    elif mutation == "file_mode":
        path.chmod(0o640)
    elif mutation == "directory_mode":
        root.chmod(0o750)
    elif mutation == "rehash_transition":
        payload = json.loads(raw)
        payload["kind"] = "LOOKUP_STARTED"
        path.write_bytes(reseal(payload))
    elif mutation == "rehash_context":
        payload = json.loads(raw)
        payload["preparation"]["calendar_origin"] = "https://other.invalid"
        payload["preparation"] = json.loads(reseal(payload["preparation"], "preparation_sha256"))
        path.write_bytes(reseal(payload))
    else:
        for index in range(2, journal.MAX_CALENDAR_JOURNAL_EVENTS + 1):
            (root / f"{index:03d}.json").write_bytes(raw)
    names = sorted(p.name for p in root.iterdir())
    _, _, requests = install_client(lambda _: pytest.fail("contact after disk mutation"))
    with pytest.raises(ValueError):
        await recover(root, subject, pin)
    assert not requests and names == sorted(p.name for p in root.iterdir())


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["same_bytes_inode", "hardlink", "extra", "root_inode"])
async def test_custody_changes_during_exchange_cannot_return_or_repair_a_receipt(
    tmp_path, publication_data, install_client, mutation
):
    root, subject = tmp_path / "journal", publication_data.registration

    def change():
        path = root / "000.json"
        if mutation == "same_bytes_inode":
            replacement = tmp_path / "replacement"
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(path)
        elif mutation == "hardlink":
            os.link(path, tmp_path / "alias")
        elif mutation == "extra":
            (root / "extra").write_bytes(b"synthetic")
        else:
            root.rename(tmp_path / "displaced-journal")
            root.mkdir(mode=0o700)

    clients, _, requests = install_client(
        lambda _: httpx.Response(200, stream=Stream([attestation()], on_chunk=change))
    )
    with pytest.raises(ValueError), prepare(root, subject) as owner:
        with pytest.raises(journal.CalendarJournalError) as caught:
            await owner.submit(allow_calendar_contact=True)
        assert caught.value.outcome_retained is False
        assert caught.value.publication_may_have_occurred is True
        with pytest.raises(ValueError):
            owner._journal.require_unchanged()
        # Restore neither files nor custody. The enclosing scope must itself refuse below.
    assert len(requests) == 1 and all(c.is_closed for c in clients)


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["preparation", "intent", "outcome"])
async def test_fsync_failures_never_dispatch_before_durable_intent_or_return_success(
    tmp_path, publication_data, install_client, monkeypatch, boundary
):
    root, subject = tmp_path / "journal", publication_data.registration
    original, file_syncs = os.fsync, 0
    fail_at = {"preparation": 1, "intent": 2, "outcome": 3}[boundary]

    def fail(fd):
        nonlocal file_syncs
        if stat.S_ISREG(os.fstat(fd).st_mode):
            file_syncs += 1
            if file_syncs >= fail_at:
                raise OSError("synthetic fsync failure")
        return original(fd)

    monkeypatch.setattr(release_io.os, "fsync", fail)
    _, _, requests = install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with pytest.raises(ValueError), prepare(root, subject) as owner:
        await owner.submit(allow_calendar_contact=True)
    assert len(requests) == (1 if boundary == "outcome" else 0)
    expected = {"preparation": [], "intent": ["000.json"], "outcome": ["000.json", "001.json"]}[
        boundary
    ]
    assert sorted(p.name for p in root.iterdir()) == expected


def test_root_symlink_and_relative_paths_are_not_adopted(tmp_path, publication_data):
    actual = tmp_path / "actual"
    pin = missing_outcome(actual, publication_data.registration)
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError):
        load(alias, pin)
    with pytest.raises(ValueError, match="absolute"):
        load(Path("relative-journal"), pin)


def test_journal_close_failure_refuses_handoff_and_next_process_can_read(
    tmp_path, publication_data, monkeypatch
):
    root = tmp_path / "journal"
    original = os.close
    with (
        pytest.raises(OSError, match="synthetic close failure"),
        prepare(root, publication_data.registration) as owner,
    ):
        pin = owner.preparation.preparation_sha256
        descriptor = owner._journal.descriptor

        def close(fd):
            original(fd)
            if fd == descriptor:
                raise OSError("synthetic close failure")

        monkeypatch.setattr(journal.os, "close", close)
    monkeypatch.undo()
    assert load(root, pin).events[0].kind == "PREPARED"
    assert child("read", root, pin).returncode == 0
