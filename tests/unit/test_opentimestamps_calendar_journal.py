"""Synthetic journal protocol tests; no calendar, chain or release authority is issued."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat

import httpx
import pytest

import mmaudit.orchestration.opentimestamps_calendar_journal as journal
import mmaudit.orchestration.opentimestamps_calendar_transport as transport
from mmaudit.models.opentimestamps_replay import replay_detached_opentimestamps_proof
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from tests.unit.test_calibration_publication import FLAGS
from tests.unit.test_calibration_publication import publication_data as publication_data
from tests.unit.test_opentimestamps_calendar import NONCE, attestation
from tests.unit.test_opentimestamps_calendar_transport import ORIGIN, Stream
from tests.unit.test_opentimestamps_calendar_transport import install_client as install_client


def prepare(root, subject):
    return journal.prepare_calibration_calendar_journal(
        evidence_root=root, subject=subject, calendar_origin=ORIGIN
    )


def recover(root, original_subject, pin, **changes):
    arguments = dict(
        evidence_root=root,
        subject=original_subject,
        expected_preparation_sha256=pin,
        calendar_origin=ORIGIN,
        allow_calendar_contact=True,
    )
    arguments.update(changes)
    return journal.recover_calibration_calendar_journal(**arguments)


def load(root, pin):
    return journal.load_calibration_calendar_journal(
        evidence_root=root, expected_preparation_sha256=pin
    )


def missing_outcome(root, subject):
    with prepare(root, subject) as owner:
        pin = owner.preparation.preparation_sha256
        owner._journal.append("POST_STARTED", owner.preparation)
    return pin


def reseal(value, field="event_sha256"):
    value = json.loads(json.dumps(value))
    value.pop(field, None)
    return stable_json({**value, field: canonical_sha256(value)}).encode()


@pytest.mark.asyncio
async def test_nonce_request_and_dispatch_intent_are_fsynced_before_the_only_post(
    tmp_path, publication_data, install_client, monkeypatch
):
    root, subject = tmp_path / "journal", publication_data.registration
    synced, nonce_calls = [], []
    original = os.fsync

    def fsync(fd):
        synced.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        original(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(transport.secrets, "token_bytes", lambda n: nonce_calls.append(n) or NONCE)

    def reply(request):
        assert synced == ["file", "directory", "file", "directory"]
        events = [json.loads((root / f"{index:03d}.json").read_bytes()) for index in range(2)]
        assert [e["kind"] for e in events] == ["PREPARED", "POST_STARTED"]
        assert events[0]["preparation"] == events[1]["preparation"]
        assert request.method == "POST" and str(request.url) == ORIGIN + "/digest"
        assert request.content.hex() == events[0]["preparation"]["commitment_hex"]
        return httpx.Response(200, stream=Stream([attestation()]))

    clients, _, requests = install_client(reply)
    with prepare(root, subject) as owner:
        preparation = owner.preparation
        assert len(requests) == 0 and nonce_calls == [16]
        assert preparation.subject_sha256 == subject.subject_sha256
        assert (
            preparation.file_sha256
            == hashlib.sha256(bytes.fromhex(subject.subject_sha256)).hexdigest()
        )
        assert (
            preparation.commitment_hex
            == hashlib.sha256(bytes.fromhex(preparation.file_sha256) + NONCE).hexdigest()
        )
        result = await owner.submit(allow_calendar_contact=True)
        with pytest.raises(ValueError, match="repeat POST"):
            await owner.submit(allow_calendar_contact=True)
    assert len(requests) == len(clients) == 1 and clients[0].is_closed
    assert [e.kind for e in result.events] == ["PREPARED", "POST_STARTED", "POST_REPLAYED"]
    assert result == load(root, preparation.preparation_sha256)
    assert replay_detached_opentimestamps_proof(
        result.detached_proof, expected_file_sha256=preparation.file_sha256
    )
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in root.iterdir())
    for event in result.events:
        assert all(
            getattr(event, flag) is (flag == "external_comparison_required") for flag in FLAGS
        )


@pytest.mark.asyncio
async def test_reopened_missing_outcome_is_original_get_without_entropy_or_second_post(
    tmp_path, publication_data, install_client, monkeypatch
):
    root, subject = tmp_path / "journal", publication_data.registration
    pin = missing_outcome(root, subject)
    before = load(root, pin)
    assert before.detached_proof is None
    monkeypatch.setattr(transport.secrets, "token_bytes", lambda _: pytest.fail("recovery entropy"))
    clients, _, requests = install_client(
        lambda _: httpx.Response(200, stream=Stream([attestation()]))
    )
    result = await recover(root, subject, pin)
    assert [e.kind for e in result.events] == [
        "PREPARED",
        "POST_STARTED",
        "LOOKUP_STARTED",
        "LOOKUP_REPLAYED",
    ]
    preparation = before.events[0].preparation
    assert all(e.preparation == preparation for e in result.events)
    assert len(requests) == 1 and requests[0].method == "GET" and requests[0].content == b""
    assert str(requests[0].url) == ORIGIN + "/timestamp/" + preparation.commitment_hex
    assert all(client.is_closed for client in clients)
    assert result == load(root, pin) and result.detached_proof is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["registration", "measurement"])
async def test_both_original_publication_phases_bind_the_binary_digest_file(
    tmp_path, publication_data, install_client, phase
):
    subject = getattr(publication_data, phase)
    install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    with prepare(tmp_path / "journal", subject) as owner:
        result = await owner.submit(allow_calendar_contact=True)
    assert result.events[0].preparation.phase == subject.phase
    assert result.events[0].preparation.subject_sha256 == subject.subject_sha256


@pytest.mark.asyncio
@pytest.mark.parametrize("allowed", [False, None, 0, 1, "true"])
async def test_consent_is_required_without_consuming_the_prepared_post_slot(
    tmp_path, publication_data, install_client, allowed
):
    _, _, requests = install_client(lambda _: pytest.fail("contact without consent"))
    with prepare(tmp_path / "journal", publication_data.registration) as owner:
        with pytest.raises(ValueError, match="authorization"):
            await owner.submit(allow_calendar_contact=allowed)
        assert [e.kind for e in owner._journal.events] == ["PREPARED"]
    assert not requests


@pytest.mark.asyncio
async def test_abandoned_preparation_and_closed_or_reconstructed_owner_cannot_post(
    tmp_path, publication_data, install_client
):
    root, subject = tmp_path / "journal", publication_data.registration
    _, _, requests = install_client(lambda _: pytest.fail("abandoned POST"))
    with prepare(root, subject) as owner:
        pin = owner.preparation.preparation_sha256
    with pytest.raises(ValueError, match="closed"):
        await owner.submit(allow_calendar_contact=True)
    with pytest.raises(ValueError, match="no dispatched"):
        await recover(root, subject, pin)
    with journal._locked_journal(root) as reopened:
        reopened.load(pin)
        with pytest.raises(ValueError, match="fresh"):
            journal.PreparedCalendarJournal(reopened, subject)
        with pytest.raises(ValueError, match="cannot POST"):
            await journal._perform(
                reopened, subject, lookup=False, allow_calendar_contact=True, timeout_seconds=10.0
            )
    with pytest.raises(FileExistsError), prepare(root, subject):
        pytest.fail("overwrote existing journal")
    assert not requests and len(load(root, pin).events) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", ["pin", "subject", "origin", "consent", "timeout"])
async def test_recovery_binding_refuses_before_contact_and_without_appending(
    tmp_path, publication_data, install_client, changed
):
    root, subject = tmp_path / "journal", publication_data.registration
    pin = missing_outcome(root, subject)
    before = load(root, pin)
    _, _, requests = install_client(lambda _: pytest.fail("wrong recovery binding"))
    changes = {
        "pin": {"expected_preparation_sha256": "f" * 64},
        "subject": {"subject": publication_data.measurement},
        "origin": {"calendar_origin": "https://different.invalid"},
        "consent": {"allow_calendar_contact": False},
        "timeout": {"timeout_seconds": 0.0},
    }[changed]
    with pytest.raises(ValueError):
        await recover(root, subject, pin, **changes)
    assert not requests and load(root, pin) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["http_error", "bad_proof", "stream_error", "cancelled"])
async def test_failed_or_cancelled_post_retains_original_context_and_never_retries(
    tmp_path, publication_data, install_client, kind
):
    root, subject = tmp_path / "journal", publication_data.registration
    failure = asyncio.CancelledError() if kind == "cancelled" else RuntimeError("synthetic detail")
    stream = Stream(
        [b"invalid" if kind == "bad_proof" else attestation()],
        failure=failure if kind in {"stream_error", "cancelled"} else None,
    )
    clients, _, requests = install_client(
        lambda _: httpx.Response(503 if kind == "http_error" else 200, stream=stream)
    )
    with prepare(root, subject) as owner:
        expected = (
            journal.CalendarJournalCancelled
            if kind == "cancelled"
            else journal.CalendarJournalError
        )
        with pytest.raises(expected) as caught:
            await owner.submit(allow_calendar_contact=True)
        assert caught.value.outcome_retained is True
        assert caught.value.preparation_sha256 == owner.preparation.preparation_sha256
        assert caught.value.publication_may_have_occurred is True
        assert caught.value.submission_context == journal._context(owner.preparation)
        with pytest.raises(ValueError, match="repeat POST"):
            await owner.submit(allow_calendar_contact=True)
    data = load(root, caught.value.preparation_sha256)
    assert data.events[-1].kind == "POST_UNCERTAIN" and data.detached_proof is None
    assert data.events[-1].failure == ("CANCELLED" if kind == "cancelled" else "EXCHANGE_REFUSED")
    assert len(requests) == 1 and all(client.is_closed for client in clients)
    assert "synthetic detail" not in stable_json(data.events[-1].model_dump(mode="json"))


@pytest.mark.asyncio
async def test_unavailable_lookups_keep_each_attempt_and_stop_at_the_fixed_bound(
    tmp_path, publication_data, install_client
):
    root, subject = tmp_path / "journal", publication_data.registration
    pin = missing_outcome(root, subject)
    clients, _, requests = install_client(lambda _: httpx.Response(404, stream=Stream()))
    for attempt in range(journal.MAX_CALENDAR_LOOKUP_ATTEMPTS):
        result = await recover(root, subject, pin)
        assert result.events[-1].kind == "LOOKUP_UNAVAILABLE" and result.detached_proof is None
        assert sum(e.kind == "LOOKUP_STARTED" for e in result.events) == attempt + 1
    with pytest.raises(ValueError, match="remaining lookup slots"):
        await recover(root, subject, pin)
    assert len(requests) == journal.MAX_CALENDAR_LOOKUP_ATTEMPTS
    assert all(request.method == "GET" for request in requests)
    assert all(client.is_closed for client in clients)


@pytest.mark.asyncio
@pytest.mark.parametrize("cancelled", [False, True])
async def test_lookup_failure_and_cancellation_are_retained_without_overwriting_missing_post(
    tmp_path, publication_data, install_client, cancelled
):
    root, subject = tmp_path / "journal", publication_data.registration
    pin = missing_outcome(root, subject)
    before = load(root, pin)
    failure = asyncio.CancelledError() if cancelled else RuntimeError("synthetic failure")
    install_client(lambda _: httpx.Response(200, stream=Stream(failure=failure)))
    expected = journal.CalendarJournalCancelled if cancelled else journal.CalendarJournalError
    with pytest.raises(expected) as caught:
        await recover(root, subject, pin)
    assert caught.value.outcome_retained is True
    after = load(root, pin)
    assert after.events[:2] == before.events
    assert [e.kind for e in after.events[2:]] == ["LOOKUP_STARTED", "LOOKUP_UNCERTAIN"]
    assert after.detached_proof is None


@pytest.mark.asyncio
@pytest.mark.parametrize("lookup", [False, True])
@pytest.mark.parametrize("status", [200, 404])
async def test_subject_mutation_across_await_never_returns_a_receipt(
    tmp_path, publication_data, install_client, lookup, status
):
    subject = publication_data.registration.model_copy(deep=True)
    root = tmp_path / "journal"

    def reply(_):
        object.__setattr__(subject, "subject_sha256", "b" * 64)
        return httpx.Response(status, stream=Stream([attestation()]))

    install_client(reply)
    if lookup:
        pin = missing_outcome(root, subject)
        with pytest.raises(journal.CalendarJournalError):
            await recover(root, subject, pin)
    else:
        with prepare(root, subject) as owner:
            pin = owner.preparation.preparation_sha256
            with pytest.raises(journal.CalendarJournalError):
                await owner.submit(allow_calendar_contact=True)
    assert load(root, pin).events[-1].kind.endswith("UNCERTAIN")


@pytest.mark.parametrize("flag", FLAGS)
@pytest.mark.parametrize("value", ["opposite", 0, 1])
def test_serialized_flags_never_create_authority(tmp_path, publication_data, flag, value):
    root = tmp_path / "journal"
    pin = missing_outcome(root, publication_data.registration)
    payload = load(root, pin).events[0].model_dump(mode="json")
    payload[flag] = not payload[flag] if value == "opposite" else value
    with pytest.raises(ValueError):
        journal.CalendarJournalEvent.model_validate_json(reseal(payload))


@pytest.mark.parametrize(
    "field,value",
    [
        ("file_sha256", "b" * 64),
        ("nonce_hex", "c" * 32),
        ("commitment_hex", "d" * 64),
        ("body_hex", "e" * 64),
        ("headers", [["Accept", "text/plain"], ["User-Agent", "test"]]),
        ("calendar_origin", "http://calendar.invalid"),
        ("calendar_origin", ORIGIN + "/path"),
        ("method", "GET"),
        ("relative_path", "timestamp/x"),
        ("file_convention", "HEX_SUBJECT"),
        ("nonce_hex", "00"),
        ("subject_sha256", "A" * 64),
        ("extra", "value"),
    ],
)
def test_self_rehashed_preparation_still_requires_exact_wire_and_file_convention(
    tmp_path, publication_data, field, value
):
    with prepare(tmp_path / "journal", publication_data.registration) as owner:
        payload = owner.preparation.model_dump(mode="json")
    payload[field] = value
    with pytest.raises(ValueError):
        journal.CalendarJournalPreparation.model_validate_json(
            reseal(payload, "preparation_sha256")
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("event_index", True),
        ("event_index", 35),
        ("kind", "POST_REPLAYED"),
        ("response_body_hex", "00"),
        ("failure", "CANCELLED"),
        ("previous_event_sha256", "a" * 64),
        ("event_sha256", "f" * 64),
        ("extra", "value"),
    ],
)
def test_malformed_event_is_not_a_success(tmp_path, publication_data, field, value):
    root = tmp_path / "journal"
    pin = missing_outcome(root, publication_data.registration)
    payload = load(root, pin).events[0].model_dump(mode="json")
    payload[field] = value
    raw = stable_json(payload) if field == "event_sha256" else reseal(payload)
    with pytest.raises(ValueError):
        journal.CalendarJournalEvent.model_validate_json(raw)


@pytest.mark.asyncio
async def test_changed_in_memory_preparation_refuses_against_durable_bytes(
    tmp_path, publication_data, install_client
):
    _, _, requests = install_client(lambda _: pytest.fail("mutated preparation"))
    with (
        pytest.raises(ValueError, match="in-memory"),
        prepare(tmp_path / "journal", publication_data.registration) as owner,
    ):
        object.__setattr__(owner.preparation, "nonce_hex", "c" * 32)
        with pytest.raises(ValueError, match="in-memory"):
            await owner.submit(allow_calendar_contact=True)
    assert not requests


@pytest.mark.asyncio
async def test_an_uncompleted_lookup_is_visible_and_consumes_an_attempt(
    tmp_path, publication_data, install_client
):
    root, subject = tmp_path / "journal", publication_data.registration
    pin = missing_outcome(root, subject)
    with journal._locked_journal(root) as owner:
        owner.load(pin)
        owner.append("LOOKUP_STARTED", owner.events[0].preparation)
    install_client(lambda _: httpx.Response(404, stream=Stream()))
    result = await recover(root, subject, pin)
    assert [e.kind for e in result.events] == [
        "PREPARED",
        "POST_STARTED",
        "LOOKUP_STARTED",
        "LOOKUP_STARTED",
        "LOOKUP_UNAVAILABLE",
    ]


@pytest.mark.asyncio
async def test_two_tasks_cannot_dispatch_the_same_fresh_owner(
    tmp_path, publication_data, install_client
):
    entered, release = asyncio.Event(), asyncio.Event()

    class PausedStream(Stream):
        async def __aiter__(self):
            entered.set()
            await release.wait()
            yield attestation()

    clients, _, requests = install_client(lambda _: httpx.Response(200, stream=PausedStream()))
    with prepare(tmp_path / "journal", publication_data.registration) as owner:
        pending = asyncio.create_task(owner.submit(allow_calendar_contact=True))
        try:
            await asyncio.wait_for(entered.wait(), 2.0)
            with pytest.raises(ValueError, match="repeat POST"):
                await owner.submit(allow_calendar_contact=True)
            release.set()
            await asyncio.wait_for(pending, 2.0)
        finally:
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
    assert len(requests) == 1 and all(c.is_closed for c in clients)


@pytest.mark.asyncio
async def test_inherited_owner_identity_cannot_dispatch(
    tmp_path, publication_data, install_client, monkeypatch
):
    _, _, requests = install_client(lambda _: pytest.fail("inherited process owner"))
    with (
        prepare(tmp_path / "journal", publication_data.registration) as owner,
        monkeypatch.context() as changed,
    ):
        changed.setattr(journal.os, "getpid", lambda: owner._journal.pid + 1)
        with pytest.raises(ValueError, match="another process"):
            await owner.submit(allow_calendar_contact=True)
    assert not requests
