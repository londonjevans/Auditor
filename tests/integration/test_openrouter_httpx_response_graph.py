from __future__ import annotations

import asyncio
import errno
from dataclasses import dataclass
from importlib.metadata import version

import httpx
import pytest

from mmaudit.models import openrouter as openrouter_module
from mmaudit.models.openrouter import OpenRouterPrivacyError


@dataclass(frozen=True)
class _LoopbackExchange:
    release_second_chunk: asyncio.Event
    request_bytes: asyncio.Future[bytes]
    finished: asyncio.Event


async def _read_http_request(reader: asyncio.StreamReader) -> bytes:
    headers = await reader.readuntil(b"\r\n\r\n")
    content_length = 0
    for line in headers.split(b"\r\n")[1:]:
        name, separator, value = line.partition(b":")
        if separator and name.strip().lower() == b"content-length":
            content_length = int(value.strip())
    return headers + (await reader.readexactly(content_length) if content_length else b"")


@pytest.mark.asyncio
async def test_pinned_httpx_response_graph_is_stable_inflight_and_idle_after_exhaustion() -> None:
    """Prove the production graph checker against a real local HTTP/1.1 stream."""

    assert version("httpx") == "0.28.1"
    assert version("httpcore") == "1.0.9"
    assert version("h11") == "0.16.0"

    exchanges: asyncio.Queue[_LoopbackExchange] = asyncio.Queue()

    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        exchange = await exchanges.get()
        try:
            request_bytes = await _read_http_request(reader)
            if not exchange.request_bytes.done():
                exchange.request_bytes.set_result(request_bytes)
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Set-Cookie: route=synthetic; Path=/; HttpOnly\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n"
                b"5\r\nhello\r\n"
            )
            await writer.drain()
            await asyncio.wait_for(exchange.release_second_chunk.wait(), timeout=5.0)
            writer.write(b"6\r\n world\r\n0\r\n\r\n")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            exchange.finished.set()

    try:
        server = await asyncio.start_server(serve, "127.0.0.1", 0)
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EPERM}:
            pytest.skip("the managed environment denies numeric-loopback listener creation")
        raise

    socket = server.sockets[0]
    host, port = socket.getsockname()[:2]
    limits = httpx.Limits(max_connections=1, max_keepalive_connections=0)
    transport = httpx.AsyncHTTPTransport(
        http1=True,
        http2=False,
        limits=limits,
        retries=0,
    )
    request_lock = asyncio.Lock()
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url=f"http://{host}:{port}/",
            follow_redirects=False,
            max_redirects=0,
            timeout=httpx.Timeout(5.0),
            trust_env=False,
        ) as client:
            owned_transport = object.__getattribute__(client, "_transport")
            owned_pool = object.__getattribute__(owned_transport, "_pool")
            pool_values = vars(owned_pool)
            connections = pool_values["_connections"]
            requests = pool_values["_requests"]
            assert type(connections) is list and connections == []
            assert type(requests) is list and requests == []

            async def run_exchange(*, exercise_negative_projections: bool) -> bytes:
                loop = asyncio.get_running_loop()
                exchange = _LoopbackExchange(
                    release_second_chunk=asyncio.Event(),
                    request_bytes=loop.create_future(),
                    finished=asyncio.Event(),
                )
                await exchanges.put(exchange)
                try:
                    async with (
                        request_lock,
                        client.stream("GET", "generation?id=synthetic") as response,
                    ):
                        request = object.__getattribute__(response, "_request")
                        assert type(request) is httpx.Request
                        assert request.method == "GET"
                        assert request.url.path == "/generation"
                        assert type(request.url.params) is httpx.QueryParams
                        assert request.url.params.multi_items() == [("id", "synthetic")]
                        assert object.__getattribute__(request, "_content") == b""
                        assert connections is pool_values["_connections"]
                        assert requests is pool_values["_requests"]
                        cookie_jar = object.__getattribute__(
                            object.__getattribute__(client, "_cookies"),
                            "jar",
                        )
                        cookie_store = object.__getattribute__(cookie_jar, "_cookies")
                        cookie_policy = object.__getattribute__(cookie_jar, "_policy")
                        assert type(cookie_store) is dict and cookie_store
                        assert type(vars(cookie_jar).get("_now")) is int
                        assert type(vars(cookie_policy).get("_now")) is int

                        if exercise_negative_projections:
                            response_values = vars(response)
                            original_stream = response_values["stream"]
                            response_values["stream"] = object()
                            try:
                                with pytest.raises(
                                    OpenRouterPrivacyError,
                                    match="in-flight response graph",
                                ):
                                    openrouter_module._provider_httpx_inflight_response_graph(
                                        owned_pool=owned_pool,
                                        request_lock=request_lock,
                                        response=response,
                                        previous=None,
                                    )
                            finally:
                                response_values["stream"] = original_stream

                            connections.append(object())
                            try:
                                with pytest.raises(
                                    OpenRouterPrivacyError,
                                    match="in-flight response graph",
                                ):
                                    openrouter_module._provider_httpx_inflight_response_graph(
                                        owned_pool=owned_pool,
                                        request_lock=request_lock,
                                        response=response,
                                        previous=None,
                                    )
                            finally:
                                connections.pop()

                        anchor = openrouter_module._provider_httpx_inflight_response_graph(
                            owned_pool=owned_pool,
                            request_lock=request_lock,
                            response=response,
                            previous=None,
                        )
                        assert len(anchor) == 13
                        assert anchor[11] is connections
                        assert anchor[12] is requests

                        iterator = response.aiter_bytes()
                        content = bytearray(await anext(iterator))
                        observed = openrouter_module._provider_httpx_inflight_response_graph(
                            owned_pool=owned_pool,
                            request_lock=request_lock,
                            response=response,
                            previous=anchor,
                        )
                        assert all(
                            current is original
                            for current, original in zip(observed, anchor, strict=True)
                        )

                        exchange.release_second_chunk.set()
                        async for chunk in iterator:
                            content.extend(chunk)
                            observed = openrouter_module._provider_httpx_inflight_response_graph(
                                owned_pool=owned_pool,
                                request_lock=request_lock,
                                response=response,
                                previous=anchor,
                            )
                            assert all(
                                current is original
                                for current, original in zip(observed, anchor, strict=True)
                            )

                        completed = openrouter_module._provider_httpx_completed_response_graph(
                            owned_pool=owned_pool,
                            request_lock=request_lock,
                            response=response,
                            previous=anchor,
                        )
                        assert completed is anchor
                        assert content == b"hello world"
                        cookie_store.clear()
                        if hasattr(cookie_jar, "_now"):
                            object.__delattr__(cookie_jar, "_now")
                        if hasattr(cookie_policy, "_now"):
                            object.__delattr__(cookie_policy, "_now")
                        assert frozenset(vars(cookie_jar)) == {
                            "_cookies",
                            "_cookies_lock",
                            "_policy",
                        }
                        assert "_now" not in vars(cookie_policy)

                finally:
                    exchange.release_second_chunk.set()
                    await asyncio.wait_for(exchange.finished.wait(), timeout=5.0)
                assert connections is pool_values["_connections"] and connections == []
                assert requests is pool_values["_requests"] and requests == []
                return await asyncio.wait_for(exchange.request_bytes, timeout=5.0)

            first_request = await run_exchange(exercise_negative_projections=True)
            second_request = await run_exchange(exercise_negative_projections=False)
            assert first_request.startswith(b"GET /generation?id=synthetic HTTP/1.1\r\n")
            assert second_request.startswith(b"GET /generation?id=synthetic HTTP/1.1\r\n")
            assert b"\r\nCookie:" not in first_request
            assert b"\r\nCookie:" not in second_request
    finally:
        server.close()
        await server.wait_closed()
