"""Real disposable loopback HTTP framing, not live TLS-origin or chain authentication.

The test-only transport rewrites a reserved .invalid origin to its own numeric
loopback listener. The public API has no injected-transport or HTTP-origin option.
All resulting observations are constructible data, never external seal evidence.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import json
from contextlib import suppress
from pathlib import Path

import httpx
import pytest

import mmaudit.orchestration.opentimestamps_calendar_journal as journal
import mmaudit.orchestration.opentimestamps_calendar_transport as calendar
from mmaudit.models.opentimestamps_replay import replay_detached_opentimestamps_proof
from tests.unit.test_calibration_publication import publication_data as publication_data

FIXTURE = Path(__file__).parents[1] / "fixtures/opentimestamps/synthetic_calendar.json"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode",
    [
        "content_length",
        "chunked",
        "close_delimited",
        "truncated_length",
        "truncated_chunked",
        "oversized_length",
        "oversized_chunked",
        "trailing_tree",
        "redirect",
        "compressed",
        "disconnect",
        "slow",
        "cookie_isolation",
        "lookup",
        "journal_roundtrip",
        "journal_disconnect_recover",
    ],
)
async def test_real_local_http_never_admits_a_prefix_retry_or_cookie_reuse(
    monkeypatch, mode, tmp_path, publication_data
):
    fixture = json.loads(FIXTURE.read_text())
    assert fixture["synthetic_only"] is True
    proof_body = bytes.fromhex(fixture["raw_reply_hex"])
    requests, tasks, clients, transports = [], set(), [], []
    first_body = asyncio.Event()
    release_body = asyncio.Event()

    async def serve(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        try:
            assert writer.get_extra_info("peername")[0] == "127.0.0.1"
            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2.0)
            lengths = [
                int(line.partition(b":")[2])
                for line in header.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            ]
            assert len(lengths) <= 1
            length = lengths[0] if lengths else 0
            assert length in (0, 32)
            body = await asyncio.wait_for(reader.readexactly(length), 2.0)
            requests.append((header, body))
            if mode == "disconnect" or (
                mode == "journal_disconnect_recover" and len(requests) == 1
            ):
                return
            status = b"302 Found" if mode == "redirect" else b"200 OK"
            extra = b"Connection: close\r\n"
            response = proof_body
            if mode == "redirect":
                extra += b"Location: https://other.invalid/digest\r\n"
            if mode == "compressed":
                extra += b"Content-Encoding: gzip\r\n"
            if mode == "cookie_isolation":
                extra += b"Set-Cookie: synthetic=private-test-cookie; Path=/\r\n"
            if mode == "trailing_tree":
                response += b"x"
            if mode in ("oversized_length", "oversized_chunked"):
                response = b"x" * 10001
            chunked = mode in ("chunked", "truncated_chunked", "oversized_chunked", "slow")
            if chunked:
                extra += b"Transfer-Encoding: chunked\r\n"
            elif mode != "close_delimited":
                declared = len(response) + (1 if mode == "truncated_length" else 0)
                extra += b"Content-Length: " + str(declared).encode() + b"\r\n"
            writer.write(b"HTTP/1.1 " + status + b"\r\n" + extra + b"\r\n")
            if chunked:
                writer.write(format(len(response), "x").encode() + b"\r\n" + response + b"\r\n")
                await writer.drain()
                first_body.set()
                if mode in ("chunked", "slow"):
                    await asyncio.wait_for(release_body.wait(), 2.0)
                if mode != "truncated_chunked":
                    writer.write(b"0\r\n\r\n")
            else:
                writer.write(response)
            await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
            with suppress(ConnectionError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 1.0)
            tasks.discard(task)

    try:
        server = await asyncio.start_server(serve, "127.0.0.1", 0, limit=16384)
    except OSError as failure:
        if failure.errno in {errno.EACCES, errno.EPERM}:
            pytest.skip("managed environment denies this disposable numeric-loopback listener")
        raise
    port = server.sockets[0].getsockname()[1]

    class LoopbackOnly(httpx.AsyncBaseTransport):
        def __init__(self):
            self.inner = httpx.AsyncHTTPTransport(
                trust_env=False, http1=True, http2=False, retries=0
            )
            self.closed = False
            transports.append(self)

        async def handle_async_request(self, request):
            assert request.url.scheme == "https" and request.url.host == "calendar.invalid"
            forwarded = httpx.Request(
                request.method,
                f"http://127.0.0.1:{port}" + request.url.raw_path.decode("ascii"),
                headers=request.headers,
                content=request.content,
                extensions=request.extensions,
            )
            return await self.inner.handle_async_request(forwarded)

        async def aclose(self):
            await self.inner.aclose()
            self.closed = True

    original = httpx.AsyncClient

    def local_client(**kwargs):
        client = original(**kwargs, transport=LoopbackOnly())
        clients.append(client)
        return client

    monkeypatch.setattr(calendar.httpx, "AsyncClient", local_client)
    # These are intentionally synthetic values, not reads of ambient credentials.
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:1")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent-synthetic-calendar-ca.pem")
    pending = None
    try:
        parameters = dict(
            calendar_origin="https://calendar.invalid",
            allow_calendar_contact=True,
            timeout_seconds=0.05 if mode == "slow" else 2.0,
        )
        if mode.startswith("journal_"):
            root = tmp_path / "journal"
            subject = publication_data.registration
            with journal.prepare_calibration_calendar_journal(
                evidence_root=root, subject=subject, calendar_origin=parameters["calendar_origin"]
            ) as owner:
                preparation = owner.preparation
                if mode == "journal_disconnect_recover":
                    with pytest.raises(journal.CalendarJournalError) as failure:
                        await owner.submit(allow_calendar_contact=True, timeout_seconds=2.0)
                    assert failure.value.outcome_retained is True
                else:
                    initial = await owner.submit(allow_calendar_contact=True, timeout_seconds=2.0)
                    assert initial.events[-1].kind == "POST_REPLAYED"
            recovered = await journal.recover_calibration_calendar_journal(
                evidence_root=root,
                expected_preparation_sha256=preparation.preparation_sha256,
                subject=subject,
                **parameters,
            )
            assert [e.kind for e in recovered.events[-2:]] == ["LOOKUP_STARTED", "LOOKUP_REPLAYED"]
            assert recovered.events[-1].response_body_hex == proof_body.hex()
            assert all(e.preparation == preparation for e in recovered.events)
            assert requests[0][0].startswith(b"POST /digest HTTP/1.1\r\n")
            assert requests[0][1].hex() == preparation.commitment_hex
            assert requests[1][0].startswith(
                b"GET /timestamp/" + preparation.commitment_hex.encode()
            )
            assert requests[1][1] == b""
            assert recovered == journal.load_calibration_calendar_journal(
                evidence_root=root, expected_preparation_sha256=preparation.preparation_sha256
            )
        elif mode == "lookup":
            result = await calendar.lookup_opentimestamps_calendar(
                commitment=b"x" * 44, **parameters
            )
            assert result.replay.attestations[0].commitment_hex == (b"x" * 44).hex()
            assert requests[0][0].startswith(b"GET /timestamp/" + (b"x" * 44).hex().encode())
            assert requests[0][1] == b""
        else:

            async def submit():
                return await calendar.submit_opentimestamps_calendar(
                    file_sha256=fixture["file_sha256"], **parameters
                )

            pending = asyncio.create_task(submit())
            if mode in ("chunked", "slow"):
                await asyncio.wait_for(first_body.wait(), 1.0)
                await asyncio.sleep(0.02)
                # The complete tree is already on the wire, but the chunked
                # message has not ended; parsing its prefix would be incorrect.
                assert not pending.done()
                if mode == "chunked":
                    release_body.set()
            if mode not in ("content_length", "chunked", "close_delimited", "cookie_isolation"):
                with pytest.raises(calendar.CalendarTransportError) as failure:
                    await asyncio.wait_for(pending, 3.0)
                assert failure.value.publication_may_have_occurred
            else:
                result = await asyncio.wait_for(pending, 3.0)
                assert result.exchange.response_body == proof_body
                assert requests[0][0].startswith(b"POST /digest HTTP/1.1\r\n")
                expected = hashlib.sha256(
                    bytes.fromhex(fixture["file_sha256"]) + result.nonce
                ).digest()
                assert requests[0][1] == expected and len(expected) == 32
                replay = replay_detached_opentimestamps_proof(
                    result.detached_proof, expected_file_sha256=fixture["file_sha256"]
                )
                assert replay.attestations == result.exchange.replay.attestations
                assert not hasattr(result, "require") and not hasattr(result, "verified")
                if mode == "cookie_isolation":
                    await submit()
        assert len(requests) == (
            2 if mode == "cookie_isolation" or mode.startswith("journal_") else 1
        )
        assert all(client.is_closed for client in clients)
        assert all(item.closed for item in transports)
        for header, _ in requests:
            assert b"accept-encoding: identity\r\n" in header.lower()
            assert b"authorization:" not in header.lower() and b"cookie:" not in header.lower()
    finally:
        release_body.set()
        if pending is not None and not pending.done():
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
        server.close()
        await server.wait_closed()
        remaining = tuple(tasks)
        for task in remaining:
            task.cancel()
        await asyncio.gather(*remaining, return_exceptions=True)
