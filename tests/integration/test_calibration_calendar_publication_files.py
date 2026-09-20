"""Real private evidence I/O and disposable reader processes, not public publication."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

import mmaudit.orchestration.calibration_calendar_publication as publisher
import mmaudit.release_io as release_io
from tests.unit.test_calibration_calendar_publication import (
    prepare_registration,
    read,
    recover,
    registration_inputs,
)
from tests.unit.test_opentimestamps_calendar import attestation
from tests.unit.test_opentimestamps_calendar_journal import reseal
from tests.unit.test_opentimestamps_calendar_transport import Stream
from tests.unit.test_opentimestamps_calendar_transport import install_client as install_client

ROOT = Path(__file__).resolve().parents[2]
READER = """
import json, sys
from pathlib import Path
from mmaudit.orchestration.calibration_calendar_publication import load_calibration_calendar_publication
data = load_calibration_calendar_publication(output_root=Path(sys.argv[1]), expected_publication_sha256=sys.argv[2])
assert not hasattr(data, 'verification')
assert data.binding.external_publication_verified is False
print(json.dumps({'subject': data.subject.subject_sha256, 'kinds': [e.kind for e in data.calendar.events]}))
"""


@pytest.mark.asyncio
async def test_fresh_process_reads_retained_subject_after_source_loss_without_native_authority(
    tmp_path, install_client
):
    state = registration_inputs(tmp_path)
    _, _, requests = install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with prepare_registration(state) as owner:
        pin = owner.binding.publication_sha256
        initial = await owner.submit(allow_calendar_contact=True)
    state.root.rename(tmp_path / "unavailable-population")
    result = subprocess.run(
        [sys.executable, "-c", READER, str(state.output), pin],
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
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "subject": initial.subject.subject_sha256,
        "kinds": ["PREPARED", "POST_STARTED", "POST_REPLAYED"],
    }
    recovered = await recover(state.output, pin)
    assert recovered.subject == initial.subject
    assert [r.method for r in requests] == ["POST", "GET"]
    assert recovered.binding.serialized_authority is False


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_subject",
        "missing_descriptor",
        "extra",
        "partial_subject",
        "partial_descriptor",
        "whitespace",
        "duplicate_key",
        "oversized",
        "subject_symlink",
        "subject_hardlink",
        "descriptor_mode",
        "root_mode",
        "calendar_symlink",
        "wrong_subject_hash",
        "rehashed_wrong_subject",
        "rehashed_wrong_preparation",
        "changed_preparation_file",
    ],
)
def test_partial_or_changed_publication_never_returns_a_repaired_prefix(tmp_path, mutation):
    state = registration_inputs(tmp_path)
    with prepare_registration(state) as owner:
        pin = owner.binding.publication_sha256
    root, subject, descriptor = (
        state.output,
        state.output / "subject.json",
        state.output / "publication.json",
    )
    if mutation == "missing_subject":
        subject.unlink()
    elif mutation == "missing_descriptor":
        descriptor.unlink()
    elif mutation == "extra":
        (root / "extra").write_bytes(b"synthetic")
    elif mutation == "partial_subject":
        subject.write_bytes(b"{")
    elif mutation == "partial_descriptor":
        descriptor.write_bytes(b"{")
    elif mutation == "whitespace":
        descriptor.write_bytes(descriptor.read_bytes() + b"\n")
    elif mutation == "duplicate_key":
        descriptor.write_bytes(b'{"schema_version":"1.0",' + descriptor.read_bytes()[1:])
    elif mutation == "oversized":
        descriptor.write_bytes(b"x" * (publisher._MAX_BINDING_BYTES + 1))
    elif mutation == "subject_symlink":
        target = tmp_path / "subject-copy"
        subject.rename(target)
        subject.symlink_to(target)
    elif mutation == "subject_hardlink":
        os.link(subject, tmp_path / "extra-alias")
    elif mutation == "descriptor_mode":
        descriptor.chmod(0o640)
    elif mutation == "root_mode":
        root.chmod(0o750)
    elif mutation == "calendar_symlink":
        calendar = root / "calendar"
        target = tmp_path / "calendar-copy"
        calendar.rename(target)
        calendar.symlink_to(target, target_is_directory=True)
    elif mutation == "changed_preparation_file":
        (root / "calendar/000.json").write_bytes(b"{")
    else:
        payload = json.loads(descriptor.read_bytes())
        if mutation == "wrong_subject_hash":
            payload["subject_file"]["sha256"] = "a" * 64
        elif mutation == "rehashed_wrong_subject":
            payload["registration_event_sha256"] = "b" * 64
        else:
            payload["preparation"]["calendar_origin"] = "https://different.invalid"
            payload["preparation"] = json.loads(
                reseal(payload["preparation"], "preparation_sha256")
            )
        raw = reseal(payload, "publication_sha256")
        descriptor.write_bytes(raw)
        # Even adopting a rehashed descriptor as data cannot bypass its subject/context joins.
        pin = json.loads(raw)["publication_sha256"]
    names = sorted(path.name for path in root.iterdir())
    with pytest.raises(ValueError):
        read(root, pin)
    assert sorted(path.name for path in root.iterdir()) == names


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["population", "subject", "descriptor", "calendar", "root"])
async def test_same_bytes_replacement_across_await_never_completes_source_owned_handoff(
    tmp_path, install_client, target
):
    state = registration_inputs(tmp_path)

    def mutate():
        if target == "root":
            state.output.rename(tmp_path / "displaced-publication")
            state.output.mkdir(mode=0o700)
            return
        path = {
            "population": state.root / "000.json",
            "subject": state.output / "subject.json",
            "descriptor": state.output / "publication.json",
            "calendar": state.output / "calendar/000.json",
        }[target]
        replacement = tmp_path / "replacement"
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(path)

    clients, _, requests = install_client(
        lambda _: httpx.Response(200, stream=Stream([attestation()], on_chunk=mutate))
    )
    with (
        pytest.raises(publisher.CalibrationCalendarPublicationError),
        prepare_registration(state) as owner,
    ):
        await owner.submit(allow_calendar_contact=True)
    assert len(requests) == 1 and all(client.is_closed for client in clients)


@pytest.mark.parametrize("target", ["population", "subject", "descriptor"])
def test_scope_exit_rechecks_source_and_retained_files(tmp_path, target):
    state = registration_inputs(tmp_path)
    with pytest.raises(ValueError), prepare_registration(state):
        path = {
            "population": state.root / "000.json",
            "subject": state.output / "subject.json",
            "descriptor": state.output / "publication.json",
        }[target]
        path.write_bytes(path.read_bytes() + b"\n")


@pytest.mark.parametrize("target", ["subject.json", "publication.json"])
def test_failed_fsync_leaves_only_incomplete_nonauthorizing_preparation(
    tmp_path, monkeypatch, target
):
    state = registration_inputs(tmp_path)
    original = os.fsync

    def fail(fd):
        path = state.output / target
        if path.exists() and path.stat().st_ino == os.fstat(fd).st_ino:
            raise OSError("synthetic publication fsync failure")
        original(fd)

    monkeypatch.setattr(release_io.os, "fsync", fail)
    with pytest.raises(ValueError), prepare_registration(state):
        pytest.fail("incomplete durable descriptor was handed off")
    assert not (state.output / "publication.json").exists()
    assert not (state.output / "calendar/001.json").exists()
    with pytest.raises(ValueError):
        read(state.output, "a" * 64)


def test_output_never_changes_or_nests_inside_original_population(tmp_path):
    state = registration_inputs(tmp_path)
    before = (state.root / "000.json").read_bytes()
    for root in (state.root, state.root / "publication", state.root.parent):
        with (
            pytest.raises(ValueError, match="separate"),
            prepare_registration(state, output_root=root),
        ):
            pytest.fail("source-overlapping output admitted")
    assert (state.root / "000.json").read_bytes() == before
    assert {path.name for path in state.root.iterdir()} == {"000.json"}


@pytest.mark.asyncio
async def test_changed_descriptor_during_get_cannot_return_a_recovery_result(
    tmp_path, install_client
):
    state = registration_inputs(tmp_path)
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with prepare_registration(state) as owner:
        pin = owner.binding.publication_sha256
        await owner.submit(allow_calendar_contact=True)

    def mutate():
        path = state.output / "publication.json"
        path.write_bytes(path.read_bytes() + b"\n")

    _, _, requests = install_client(
        lambda _: httpx.Response(200, stream=Stream([attestation()], on_chunk=mutate))
    )
    with pytest.raises(publisher.CalibrationCalendarPublicationError):
        await recover(state.output, pin)
    assert [request.method for request in requests] == ["POST", "GET"]


def test_source_file_identity_is_retained_while_calendar_preparation_is_created(
    tmp_path, monkeypatch
):
    state = registration_inputs(tmp_path)
    original = publisher.write_json_evidence

    def write(**kwargs):
        if kwargs["relative_path"] == "publication.json":
            path = state.output / "subject.json"
            replacement = tmp_path / "replacement"
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(path)
        return original(**kwargs)

    monkeypatch.setattr(publisher, "write_json_evidence", write)
    with pytest.raises(ValueError), prepare_registration(state):
        pytest.fail("adopted a replacement subject during preparation")
    assert not (state.output / "calendar/001.json").exists()


def test_source_drift_during_child_close_prevents_enclosing_handoff(tmp_path, monkeypatch):
    state = registration_inputs(tmp_path)
    original, changed = os.close, False
    with pytest.raises(ValueError), prepare_registration(state) as owner:
        descriptor = owner._calendar._journal.descriptor

        def close(fd):
            nonlocal changed
            original(fd)
            if fd == descriptor and not changed:
                changed = True
                source = state.root / "000.json"
                source.write_bytes(source.read_bytes() + b"\n")

        monkeypatch.setattr(publisher.os, "close", close)
    assert changed
