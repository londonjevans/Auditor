"""Isolated transport mechanics; ordinary observations never establish external authority."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import FrozenInstanceError

import httpx
import pytest

import mmaudit.orchestration.opentimestamps_calendar_transport as transport
from mmaudit.models.opentimestamps_calendar import CalendarCommitmentUnavailable
from mmaudit.models.opentimestamps_replay import replay_detached_opentimestamps_proof
from mmaudit.orchestration.calibration_publication import CalibrationPublicationSubject
from tests.unit.test_calibration_publication import publication_data as publication_data
from tests.unit.test_opentimestamps_calendar import (
    DIGEST,
    NONCE,
    PENDING,
    attestation,
    blob,
    siblings,
)

ORIGIN = "https://calendar.invalid"


class Stream(httpx.AsyncByteStream):
    def __init__(self, chunks=(), *, on_chunk=None, on_close=None, failure=None):
        self.chunks = chunks
        self.on_chunk = on_chunk
        self.on_close = on_close
        self.failure = failure
        self.closed = False
        self.delivered = 0

    async def __aiter__(self):
        for chunk in self.chunks:
            if self.on_chunk:
                self.on_chunk()
            self.delivered += 1
            yield chunk
        if self.failure:
            raise self.failure

    async def aclose(self):
        self.closed = True
        if self.on_close:
            await self.on_close()


@pytest.fixture
def install_client(monkeypatch):
    original = httpx.AsyncClient
    clients, settings, requests = [], [], []

    def install(handler):
        def record(supplied):
            requests.append(supplied)
            return handler(supplied)

        def factory(**kwargs):
            settings.append(dict(kwargs))
            client = original(**kwargs, transport=httpx.MockTransport(record))
            clients.append(client)
            return client

        monkeypatch.setattr(transport.httpx, "AsyncClient", factory)
        return clients, settings, requests

    return install


def submit(**changes):
    args = dict(file_sha256=DIGEST.hex(), calendar_origin=ORIGIN, allow_calendar_contact=True)
    args.update(changes)
    return transport.submit_opentimestamps_calendar(**args)


@pytest.mark.asyncio
async def test_owned_nonce_exact_wire_and_closed_client_are_bound_to_detached_file(
    install_client, monkeypatch
):
    nonce_calls = []
    monkeypatch.setattr(
        transport.secrets, "token_bytes", lambda size: nonce_calls.append(size) or NONCE
    )
    stream = Stream([attestation()[:4], attestation()[4:]])
    clients, settings, requests = install_client(lambda _: httpx.Response(200, stream=stream))
    result = await submit()
    assert nonce_calls == [16] and result.nonce == NONCE
    assert len(requests) == len(clients) == 1 and clients[0].is_closed and stream.closed
    request = requests[0]
    expected = hashlib.sha256(DIGEST + NONCE).digest()
    assert str(request.url) == ORIGIN + "/digest" and request.method == "POST"
    assert request.content == expected and result.exchange.request.body == expected
    assert request.headers["content-length"] == "32"
    assert request.headers["accept"] == "application/vnd.opentimestamps.v1"
    assert request.headers["accept-encoding"] == "identity"
    assert request.headers["connection"] == "close"
    assert "authorization" not in request.headers and "cookie" not in request.headers
    assert settings[0]["verify"] is True and settings[0]["trust_env"] is False
    assert settings[0]["follow_redirects"] is False and settings[0]["max_redirects"] == 0
    assert settings[0]["http1"] is True and settings[0]["http2"] is False
    assert settings[0]["limits"].max_connections == 1
    assert settings[0]["limits"].max_keepalive_connections == 0
    replay = replay_detached_opentimestamps_proof(
        result.detached_proof, expected_file_sha256=DIGEST.hex()
    )
    assert replay.attestations == result.exchange.replay.attestations
    assert replay.attestations[0].commitment_hex == expected.hex()
    assert not hasattr(result, "require") and not hasattr(result.exchange, "verified")
    with pytest.raises(FrozenInstanceError):
        result.nonce = b"x" * 16


@pytest.mark.asyncio
async def test_real_nonce_source_produces_distinct_contexts_without_mock_entropy(install_client):
    clients, _, requests = install_client(
        lambda _: httpx.Response(200, stream=Stream([attestation()]))
    )
    first, second = await submit(), await submit()
    assert len(first.nonce) == len(second.nonce) == 16 and first.nonce != second.nonce
    assert requests[0].content != requests[1].content
    assert all(client.is_closed for client in clients)


@pytest.mark.asyncio
@pytest.mark.parametrize("allowed", [False, None, 0, 1, "true"])
@pytest.mark.parametrize("operation", ["submit", "lookup", "calibration"])
async def test_absent_exact_contact_consent_refuses_before_entropy_or_client(
    monkeypatch, allowed, operation
):
    def forbidden(*args, **kwargs):
        pytest.fail("unauthorized preflight touched entropy or transport")

    monkeypatch.setattr(transport.secrets, "token_bytes", forbidden)
    monkeypatch.setattr(transport, "_new_client", forbidden)
    with pytest.raises(ValueError, match="authorization"):
        if operation == "submit":
            await submit(allow_calendar_contact=allowed)
        elif operation == "lookup":
            await transport.lookup_opentimestamps_calendar(
                commitment=DIGEST, calendar_origin=ORIGIN, allow_calendar_contact=allowed
            )
        else:
            await transport.submit_calibration_publication_calendar(
                subject=None, calendar_origin=ORIGIN, allow_calendar_contact=allowed
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "origin",
    [
        None,
        b"https://calendar.invalid",
        "",
        "http://calendar.invalid",
        "HTTPS://calendar.invalid",
        "https://CALENDAR.invalid",
        "https://calendar.invalid/",
        "https://calendar.invalid/digest",
        "https://calendar.invalid?",
        "https://calendar.invalid#",
        "https://user:synthetic@calendar.invalid",
        "https://@calendar.invalid",
        "https://calendar.invalid%2fpath",
        "https://calendar.invalid\\path",
        "https://calendar.invalid\n",
        "https://cálendar.invalid",
        "https://calendar.invalid:0",
        "https://calendar.invalid:65536",
        "https://calendar.invalid:443",
        "https://" + "a" * 513,
    ],
)
async def test_noncanonical_or_non_https_origins_cannot_dispatch(monkeypatch, origin):
    monkeypatch.setattr(
        transport, "_new_client", lambda _: pytest.fail("invalid origin dispatched")
    )
    with pytest.raises(ValueError, match="HTTPS origin"):
        await submit(calendar_origin=origin)


@pytest.mark.asyncio
@pytest.mark.parametrize("timeout", [None, True, 1, 0.0, 0.049, 60.01, float("nan"), float("inf")])
async def test_unbounded_or_inexact_timeout_cannot_dispatch(monkeypatch, timeout):
    monkeypatch.setattr(
        transport, "_new_client", lambda _: pytest.fail("invalid timeout dispatched")
    )
    with pytest.raises(ValueError, match="bounded float"):
        await submit(timeout_seconds=timeout)


@pytest.mark.asyncio
@pytest.mark.parametrize("digest", [None, "", "AB" * 32, "g" * 64])
async def test_invalid_file_digest_does_not_generate_nonce_or_dispatch(monkeypatch, digest):
    monkeypatch.setattr(
        transport.secrets, "token_bytes", lambda _: pytest.fail("invalid digest generated entropy")
    )
    monkeypatch.setattr(
        transport, "_new_client", lambda _: pytest.fail("invalid digest dispatched")
    )
    with pytest.raises(ValueError):
        await submit(file_sha256=digest)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [201, 204, 301, 302, 307, 308, 400, 404, 413, 429, 500])
async def test_failed_status_never_reads_private_error_body_or_retries(install_client, status):
    stream = Stream([b"PRIVATE_ERROR_CANARY"], on_chunk=lambda: pytest.fail("error body consumed"))
    clients, _, requests = install_client(
        lambda _: httpx.Response(
            status, headers={"location": "https://other.invalid"}, stream=stream
        )
    )
    with pytest.raises(transport.CalendarTransportError) as failure:
        await submit()
    assert failure.value.publication_may_have_occurred is True
    context = failure.value.submission_context
    assert context is not None and context.file_sha256 == DIGEST.hex()
    assert context.calendar_origin == ORIGIN and len(context.nonce) == 16
    assert context.request.body == requests[0].content
    assert context.request.body == hashlib.sha256(DIGEST + context.nonce).digest()
    assert "PRIVATE_ERROR_CANARY" not in str(failure.value)
    assert len(requests) == 1 and clients[0].is_closed and stream.closed


@pytest.mark.asyncio
async def test_lookup404_is_not_a_success_or_a_post_uncertainty(install_client):
    stream = Stream([b"PRIVATE_ERROR_CANARY"])
    clients, _, requests = install_client(lambda _: httpx.Response(404, stream=stream))
    with pytest.raises(CalendarCommitmentUnavailable):
        await transport.lookup_opentimestamps_calendar(
            commitment=b"x" * 44, calendar_origin=ORIGIN, allow_calendar_contact=True
        )
    assert requests[0].method == "GET" and requests[0].content == b""
    assert requests[0].url.path == "/timestamp/" + (b"x" * 44).hex()
    assert stream.delivered == 0 and stream.closed and clients[0].is_closed


@pytest.mark.asyncio
async def test_lookup_replays_44_byte_commitment_without_nonce_or_following_pending_uri(
    install_client, monkeypatch
):
    monkeypatch.setattr(
        transport.secrets, "token_bytes", lambda _: pytest.fail("lookup generated nonce")
    )
    body = attestation(PENDING, blob(b"http://127.0.0.1/private"))
    clients, _, requests = install_client(lambda _: httpx.Response(200, stream=Stream([body])))
    result = await transport.lookup_opentimestamps_calendar(
        commitment=b"x" * 44, calendar_origin=ORIGIN, allow_calendar_contact=True
    )
    assert result.replay.attestations[0].commitment_hex == (b"x" * 44).hex()
    assert "127.0.0.1" not in repr(result.replay)
    assert len(requests) == 1 and clients[0].is_closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers",
    [
        [("Content-Length", "10001")],
        [("Content-Length", "-1")],
        [("Content-Length", "garbage")],
        [("Content-Length", "000001")],
        [("Content-Length", "1"), ("Content-Length", "2")],
        [("Transfer-Encoding", "chunked"), ("Content-Length", "1")],
        [("Transfer-Encoding", "gzip")],
        [("Content-Encoding", "gzip")],
        [("Content-Encoding", "deflate")],
        [("Content-Encoding", "identity"), ("Content-Encoding", "identity")],
        [("X-Large", "x" * 16385)],
        [("X-Count", "x")] * 129,
    ],
)
async def test_bad_framing_compression_or_header_bounds_refuse_before_body(install_client, headers):
    stream = Stream([attestation()], on_chunk=lambda: pytest.fail("bad header body consumed"))
    clients, _, _ = install_client(lambda _: httpx.Response(200, headers=headers, stream=stream))
    with pytest.raises(transport.CalendarTransportError):
        await submit()
    assert clients[0].is_closed and stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    [
        "declared_short",
        "declared_long",
        "extra",
        "truncated",
        "unsupported",
        "raw_failure",
        "empty",
    ],
)
async def test_incomplete_or_unreplayable_body_cannot_become_an_observation(install_client, kind):
    body = attestation()
    headers = {}
    if kind == "declared_short":
        headers["content-length"] = str(len(body) - 1)
    elif kind == "declared_long":
        headers["content-length"] = str(len(body) + 1)
    elif kind == "extra":
        body += b"x"
    elif kind == "truncated":
        body = body[:-1]
    elif kind == "unsupported":
        body = b"\x03" + body
    elif kind == "empty":
        body = b""
    stream = Stream(
        [body], failure=RuntimeError("PRIVATE_STREAM_CANARY") if kind == "raw_failure" else None
    )
    clients, _, _ = install_client(lambda _: httpx.Response(200, headers=headers, stream=stream))
    with pytest.raises(transport.CalendarTransportError) as failure:
        await submit()
    assert failure.value.publication_may_have_occurred and "PRIVATE_STREAM_CANARY" not in str(
        failure.value
    )
    assert stream.closed and clients[0].is_closed


@pytest.mark.asyncio
@pytest.mark.parametrize("extra", [False, True])
async def test_body_bound_is_checked_across_raw_chunks_without_truncating_a_prefix(
    install_client, extra
):
    body = siblings([attestation(b"opaque-a", b"a" * 8192), attestation(b"opaque-b", b"b" * 1785)])
    assert len(body) == 10000
    stream = Stream([body[:6000], body[6000:]] + ([b"x"] if extra else []))
    clients, _, _ = install_client(lambda _: httpx.Response(200, stream=stream))
    if extra:
        with pytest.raises(transport.CalendarTransportError):
            await submit()
    else:
        result = await submit()
        assert result.exchange.response_body == body
    assert clients[0].is_closed and stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["body", "close"])
@pytest.mark.parametrize("field", ["request", "response_request", "status", "headers"])
async def test_awaited_request_response_mutation_cannot_hide_behind_cleanup(
    install_client, stage, field
):
    objects = {}

    def mutate():
        if field == "request":
            objects["request"].headers["X-Rewritten"] = "synthetic"
        elif field == "response_request":
            objects["response"].request = httpx.Request("GET", ORIGIN)
        elif field == "status":
            objects["response"].status_code = 201
        else:
            objects["response"].headers["X-Rewritten"] = "synthetic"

    async def close():
        if stage == "close":
            mutate()

    stream = Stream([attestation()], on_chunk=mutate if stage == "body" else None, on_close=close)

    def handler(supplied):
        objects["request"] = supplied
        objects["response"] = httpx.Response(200, stream=stream)
        return objects["response"]

    clients, _, _ = install_client(handler)
    with pytest.raises(transport.CalendarTransportError):
        await submit()
    assert clients[0].is_closed and stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [httpx.ConnectError("PRIVATE_CONNECT_CANARY"), httpx.ReadTimeout("PRIVATE_TIMEOUT_CANARY")],
)
async def test_transport_failures_are_uncertain_and_never_retried(install_client, failure):
    def handler(_):
        raise failure

    clients, _, requests = install_client(handler)
    with pytest.raises(transport.CalendarTransportError) as caught:
        await submit()
    assert caught.value.publication_may_have_occurred
    assert "CANARY" not in str(caught.value) and len(requests) == 1 and clients[0].is_closed


@pytest.mark.asyncio
async def test_slow_stream_hits_whole_exchange_deadline_and_closes(install_client):
    class Slow(Stream):
        async def __aiter__(self):
            await asyncio.sleep(2)
            yield attestation()

    stream = Slow()
    clients, _, requests = install_client(lambda _: httpx.Response(200, stream=stream))
    with pytest.raises(transport.CalendarTransportError):
        await asyncio.wait_for(submit(timeout_seconds=0.05), 1.0)
    assert stream.closed and clients[0].is_closed and len(requests) == 1


@pytest.mark.asyncio
async def test_cancellation_propagates_after_owned_cleanup_without_a_receipt(install_client):
    entered = asyncio.Event()

    class Waiting(Stream):
        async def __aiter__(self):
            entered.set()
            await asyncio.Event().wait()
            yield attestation()

    stream = Waiting()
    clients, _, requests = install_client(lambda _: httpx.Response(200, stream=stream))
    task = asyncio.create_task(submit())
    await asyncio.wait_for(entered.wait(), 1.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError) as failure:
        await asyncio.wait_for(task, 1.0)
    assert type(failure.value) is transport.CalendarSubmissionCancelled
    assert task.cancelled() and failure.value.publication_may_have_occurred
    context = failure.value.submission_context
    assert context.request.body == requests[0].content
    assert context.request.body == hashlib.sha256(DIGEST + context.nonce).digest()
    assert stream.closed and clients[0].is_closed and len(requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["exception", "timeout"])
async def test_cleanup_failure_cannot_publish_an_observation(install_client, monkeypatch, mode):
    monkeypatch.setattr(transport, "_CLEANUP_SECONDS", 0.05)
    clients, _, _ = install_client(lambda _: httpx.Response(200, stream=Stream([attestation()])))
    original = transport._new_client

    def factory(timeout):
        client = original(timeout)
        close = client.aclose

        async def failed_close():
            await close()
            if mode == "timeout":
                await asyncio.sleep(2)
            raise RuntimeError("PRIVATE_CLOSE_CANARY")

        client.aclose = failed_close
        return client

    monkeypatch.setattr(transport, "_new_client", factory)
    with pytest.raises(transport.CalendarTransportError) as failure:
        await asyncio.wait_for(submit(), 1.0)
    assert failure.value.publication_may_have_occurred and "PRIVATE_CLOSE_CANARY" not in str(
        failure.value
    )
    assert clients[0].is_closed


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["registration", "measurement"])
async def test_calibration_digest_file_convention_never_sends_full_subject(
    install_client, monkeypatch, publication_data, phase
):
    subject = getattr(publication_data, phase)
    monkeypatch.setattr(transport.secrets, "token_bytes", lambda _: NONCE)
    clients, _, requests = install_client(
        lambda _: httpx.Response(200, stream=Stream([attestation()]))
    )
    result = await transport.submit_calibration_publication_calendar(
        subject=subject, calendar_origin=ORIGIN, allow_calendar_contact=True
    )
    file_digest = hashlib.sha256(bytes.fromhex(subject.subject_sha256)).digest()
    assert result.subject_sha256 == subject.subject_sha256
    assert result.submission.file_sha256 == file_digest.hex()
    assert requests[0].content == hashlib.sha256(file_digest + NONCE).digest()
    assert len(requests[0].content) == 32
    assert requests[0].content != bytes.fromhex(subject.subject_sha256)
    assert (
        result.submission.file_sha256 != hashlib.sha256(subject.subject_sha256.encode()).hexdigest()
    )
    replay = replay_detached_opentimestamps_proof(
        result.submission.detached_proof, expected_file_sha256=file_digest.hex()
    )
    assert len(replay.attestations) == 1 and clients[0].is_closed
    assert not hasattr(result, "require") and not subject.release_authorized


@pytest.mark.asyncio
@pytest.mark.parametrize("coherent", [False, True])
async def test_subject_change_while_awaiting_transport_is_retained_as_uncertain(
    install_client, publication_data, coherent
):
    subject = CalibrationPublicationSubject.model_validate_json(
        publication_data.registration.model_dump_json(), strict=True
    )

    def mutate():
        if coherent:
            subject.__dict__.update(publication_data.measurement.__dict__)
        else:
            object.__setattr__(subject, "subject_sha256", "f" * 64)

    stream = Stream([attestation()], on_chunk=mutate)
    clients, _, requests = install_client(lambda _: httpx.Response(200, stream=stream))
    with pytest.raises(transport.CalendarTransportError, match="subject binding") as failure:
        await transport.submit_calibration_publication_calendar(
            subject=subject, calendar_origin=ORIGIN, allow_calendar_contact=True
        )
    assert (
        failure.value.publication_may_have_occurred and len(requests) == 1 and clients[0].is_closed
    )
    assert failure.value.submission_context.request.body == requests[0].content


@pytest.mark.asyncio
async def test_client_creation_failure_retains_context_without_claiming_dispatch(monkeypatch):
    def unavailable(_):
        raise RuntimeError("PRIVATE_SETUP_CANARY")

    monkeypatch.setattr(transport, "_new_client", unavailable)
    with pytest.raises(transport.CalendarTransportError) as failure:
        await submit()
    assert not failure.value.publication_may_have_occurred
    context = failure.value.submission_context
    assert context.request.body == hashlib.sha256(DIGEST + context.nonce).digest()
    assert "PRIVATE_SETUP_CANARY" not in str(failure.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers", [{"Content-Encoding": "IDENTITY"}, {"Transfer-Encoding": "Chunked"}]
)
async def test_framing_token_case_does_not_change_its_protocol_meaning(install_client, headers):
    install_client(lambda _: httpx.Response(200, headers=headers, stream=Stream([attestation()])))
    assert (await submit()).exchange.response_body == attestation()


@pytest.mark.asyncio
async def test_oversized_raw_chunk_is_rejected_before_requesting_another_chunk(install_client):
    stream = Stream([b"x" * 65536, b"must not be consumed"])
    clients, _, _ = install_client(lambda _: httpx.Response(200, stream=stream))
    with pytest.raises(transport.CalendarTransportError):
        await submit()
    assert stream.delivered == 1 and stream.closed and clients[0].is_closed
