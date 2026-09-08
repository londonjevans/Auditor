"""Owned, expiring loopback transport for incomplete frozen reads; never a chain or authority."""

from __future__ import annotations

import math
import re
import socket
import threading
import time
from contextlib import suppress
from typing import Any, Literal, SupportsIndex

from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.scanners.fork_rpc import PinnedForkObservation
from mmaudit.scanners.offline_fork_rpc import (
    _MAX_REQUEST_BYTES,
    _MAX_RESPONSE_BYTES,
    OfflineForkRpcError,
    OfflineForkRpcReplay,
)
from mmaudit.scanners.read_only_rpc import _close_connection, _encode_json

_MAX_HEADER_BYTES = 16 * 1024
_MAX_CONNECTIONS = 10_000
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_TIMEOUT_SECONDS = 5.0
_MAX_LIFETIME_SECONDS = 3600.0
_SHUTDOWN_SECONDS = 2.0
_POLL_SECONDS = 0.05
_ALLOWED_HEADERS = frozenset(
    {
        "host",
        "content-type",
        "content-length",
        "connection",
        "accept",
        "accept-encoding",
        "user-agent",
    }
)
_ERROR_BODY = _encode_json(
    {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32600, "message": "offline read request invalid or unavailable"},
    }
)


class OfflineForkRpcLeaseError(RuntimeError):
    """The owned read service is invalid, unavailable, exhausted or not cleanly closed."""


class _HttpRequestError(ValueError):
    pass


def _parse_http_head(head: bytes, expected_host: str) -> int:
    """Admit exactly one local POST with unambiguous bounded, uncompressed JSON framing."""

    if not 4 <= len(head) <= _MAX_HEADER_BYTES or not head.endswith(b"\r\n\r\n"):
        raise _HttpRequestError("offline HTTP framing invalid")
    lines = head[:-4].split(b"\r\n")
    if not 2 <= len(lines) <= 65 or lines[0] not in {b"POST / HTTP/1.0", b"POST / HTTP/1.1"}:
        raise _HttpRequestError("offline HTTP framing invalid")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if (
            not separator
            or re.fullmatch(rb"[A-Za-z][A-Za-z-]*", name) is None
            or any(byte < 32 or byte > 126 for byte in value)
        ):
            raise _HttpRequestError("offline HTTP framing invalid")
        key = name.decode("ascii").lower()
        if key not in _ALLOWED_HEADERS or key in headers:
            raise _HttpRequestError("offline HTTP framing invalid")
        headers[key] = value.decode("ascii").strip(" ")
    length = headers.get("content-length", "")
    if (
        headers.get("host") != expected_host
        or headers.get("content-type", "").lower().replace(" ", "")
        not in {"application/json", "application/json;charset=utf-8"}
        or re.fullmatch(r"[1-9][0-9]{0,6}", length) is None
        or not 2 <= int(length) <= _MAX_REQUEST_BYTES
        or headers.get("connection", "close").lower() not in {"close", "keep-alive"}
    ):
        raise _HttpRequestError("offline HTTP framing invalid")
    return int(length)


def _bounded_seconds(value: float, maximum: float) -> bool:
    return type(value) in {int, float} and 0.05 <= value <= maximum and math.isfinite(value)


class OfflineForkRpcLease:
    """One-shot fixed loopback listener over admitted reads, with no upstream or tool dispatch.

    A single worker bounds concurrency; each connection gets one request and one absolute
    deadline. Lifetime traffic counts received bytes plus reserved response bytes. Exhaustion,
    expiry, failed source revalidation or incomplete cleanup cannot produce a clean stop.
    This object grants no matrix, isolation, state-completeness or audit authority.
    """

    def __init__(
        self,
        replay: OfflineForkRpcReplay,
        *,
        timeout_seconds: float = 2.0,
        lifetime_seconds: float = 300.0,
        max_connections: int = _MAX_CONNECTIONS,
        max_total_bytes: int = _MAX_TOTAL_BYTES,
    ) -> None:
        if (
            type(replay) is not OfflineForkRpcReplay
            or not _bounded_seconds(timeout_seconds, _MAX_TIMEOUT_SECONDS)
            or not _bounded_seconds(lifetime_seconds, _MAX_LIFETIME_SECONDS)
            or type(max_connections) is not int
            or not 1 <= max_connections <= _MAX_CONNECTIONS
            or type(max_total_bytes) is not int
            or not 1024 <= max_total_bytes <= _MAX_TOTAL_BYTES
        ):
            raise OfflineForkRpcLeaseError("offline lease input or bounds invalid")
        self._replay = replay
        self._timeout_seconds = float(timeout_seconds)
        self._lifetime_seconds = float(lifetime_seconds)
        self._max_connections = max_connections
        self._max_total_bytes = max_total_bytes
        self._lock = threading.Lock()
        self._stop_requested = threading.Event()
        self._shutdown_failed = threading.Event()
        self._finished = threading.Event()
        self._listener: socket.socket | None = None
        self._active: socket.socket | None = None
        self._worker: threading.Thread | None = None
        self._start_attempted = False
        self._stop_attempted = False
        self._stopped_cleanly = False
        self._failure: str | None = None
        self._deadline = 0.0
        self._host = ""
        self._connection_count = 0
        self._byte_count = 0

    def __enter__(self) -> OfflineForkRpcLease:
        self.start()
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: object | None,
    ) -> None:
        self.stop()

    def __copy__(self) -> OfflineForkRpcLease:
        raise TypeError("offline leases cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> OfflineForkRpcLease:
        raise TypeError("offline leases cannot be copied")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        raise TypeError("offline leases cannot be serialized")

    @property
    def source_binding(self) -> ManifestFileBinding:
        return self._replay.source_binding

    @property
    def observation(self) -> PinnedForkObservation:
        return self._replay.observation

    @property
    def runtime_authority(self) -> Literal[False]:
        return False

    @property
    def complete_state(self) -> Literal[False]:
        return False

    @property
    def stopped_cleanly(self) -> bool:
        with self._lock:
            return self._stopped_cleanly

    @property
    def endpoint(self) -> str:
        with self._lock:
            if (
                self._listener is None
                or self._worker is None
                or not self._worker.is_alive()
                or self._stop_requested.is_set()
                or self._failure is not None
                or time.monotonic() >= self._deadline
            ):
                raise OfflineForkRpcLeaseError("offline lease is not running")
            try:
                host, port = self._listener.getsockname()
            except OSError:
                raise OfflineForkRpcLeaseError("offline lease listener unavailable") from None
            if host != "127.0.0.1" or f"{host}:{port}" != self._host:
                raise OfflineForkRpcLeaseError("offline lease listener identity differs")
            return "http://" + self._host

    def start(self) -> None:
        """Reverify the admitted archive before reserving one exclusive numeric loopback port."""

        with self._lock:
            if self._start_attempted:
                raise OfflineForkRpcLeaseError("offline lease cannot be started twice")
            self._start_attempted = True
        listener: socket.socket | None = None
        try:
            OfflineForkRpcReplay.verify_source(self._replay)
            with self._lock:
                if self._stop_requested.is_set():
                    raise OfflineForkRpcLeaseError("offline lease startup cancelled")
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.bind(("127.0.0.1", 0))
                listener.listen(8)
                listener.settimeout(_POLL_SECONDS)
                self._host = f"127.0.0.1:{listener.getsockname()[1]}"
                self._listener = listener
                self._deadline = time.monotonic() + self._lifetime_seconds
                worker = threading.Thread(
                    target=self._serve,
                    args=(listener,),
                    name="mmaudit-offline-fork-reads",
                    daemon=True,
                )
                self._worker = worker
                worker.start()
        except BaseException:
            if listener is not None:
                _close_connection(listener)
            with self._lock:
                self._listener = None
                self._failure = "offline lease startup failed"
            self._finished.set()
            raise OfflineForkRpcLeaseError("offline lease startup failed") from None

    def stop(self, deadline: float | None = None) -> None:
        """Close owned sockets, join and verify within the earlier caller/fixed shutdown bound."""

        now = time.monotonic()
        if deadline is not None and (
            type(deadline) not in {int, float}
            or (type(deadline) is float and not math.isfinite(deadline))
        ):
            raise OfflineForkRpcLeaseError("offline lease shutdown deadline invalid")
        limit = (
            max(now, min(now + _SHUTDOWN_SECONDS, deadline))
            if deadline is not None
            else now + _SHUTDOWN_SECONDS
        )
        self._stop_requested.set()
        if not self._lock.acquire(timeout=max(0.0, limit - time.monotonic())):
            self._shutdown_failed.set()
            raise OfflineForkRpcLeaseError("offline lease shutdown lock deadline exceeded")
        try:
            if not self._start_attempted:
                raise OfflineForkRpcLeaseError("offline lease was not started")
            if self._stopped_cleanly:
                return
            if self._stop_attempted or self._shutdown_failed.is_set():
                raise OfflineForkRpcLeaseError("offline lease shutdown previously failed")
            self._stop_attempted = True
            if self._failure is None:
                self._failure = self._exhaustion_reason()
            listener, active, worker = self._listener, self._active, self._worker
        finally:
            self._lock.release()
        for connection in (listener, active):
            if connection is not None:
                _close_connection(connection)
        if worker is not None and worker.ident is not None:
            worker.join(timeout=max(0.0, limit - time.monotonic()))
        if not self._lock.acquire(timeout=max(0.0, limit - time.monotonic())):
            self._shutdown_failed.set()
            raise OfflineForkRpcLeaseError("offline lease shutdown verification deadline exceeded")
        try:
            if (
                worker is None
                or worker.is_alive()
                or not self._finished.is_set()
                or self._failure is not None
                or time.monotonic() > limit
            ):
                self._shutdown_failed.set()
                raise OfflineForkRpcLeaseError("offline lease did not close and verify cleanly")
            self._stopped_cleanly = True
        finally:
            self._lock.release()

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if self._stop_requested.is_set() or remaining <= 0:
            raise TimeoutError("offline connection deadline exceeded")
        return remaining

    def _exhaustion_reason(self) -> str | None:
        if time.monotonic() >= self._deadline:
            return "offline lease lifetime expired"
        if (
            self._connection_count >= self._max_connections
            or self._byte_count >= self._max_total_bytes
        ):
            return "offline lease service budget exhausted"
        return None

    def _consume_bytes(self, count: int) -> None:
        with self._lock:
            if self._byte_count + count > self._max_total_bytes:
                self._byte_count = self._max_total_bytes
                self._failure = "offline lease traffic budget exhausted"
                self._stop_requested.set()
                raise _HttpRequestError("offline traffic budget exhausted")
            self._byte_count += count

    def _receive(self, connection: socket.socket, size: int, deadline: float) -> bytes:
        with self._lock:
            size = min(size, self._max_total_bytes - self._byte_count)
        if size <= 0:
            self._consume_bytes(1)
        connection.settimeout(self._remaining(deadline))
        body = connection.recv(size)
        if not body:
            raise _HttpRequestError("offline HTTP body incomplete")
        self._consume_bytes(len(body))
        return body

    def _read_body(self, connection: socket.socket, deadline: float) -> bytes:
        buffer = bytearray()
        while b"\r\n\r\n" not in buffer:
            if len(buffer) >= _MAX_HEADER_BYTES:
                raise _HttpRequestError("offline HTTP header exceeds bound")
            buffer.extend(
                self._receive(connection, min(4096, _MAX_HEADER_BYTES - len(buffer)), deadline)
            )
        end = buffer.index(b"\r\n\r\n") + 4
        length = _parse_http_head(bytes(buffer[:end]), self._host)
        body = bytearray(buffer[end:])
        while len(body) < length:
            body.extend(self._receive(connection, min(4096, length - len(body) + 1), deadline))
        if len(body) != length:
            raise _HttpRequestError("offline HTTP trailing data refused")
        return bytes(body)

    def _send(self, connection: socket.socket, status: int, body: bytes, deadline: float) -> None:
        if len(body) > _MAX_RESPONSE_BYTES:
            raise _HttpRequestError("offline response exceeds bound")
        label = {200: "OK", 400: "Bad Request", 503: "Service Unavailable"}[status]
        head = (
            f"HTTP/1.1 {status} {label}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n"
        ).encode("ascii")
        self._consume_bytes(len(head) + len(body))
        connection.settimeout(self._remaining(deadline))
        connection.sendall(head + body)

    def _handle(self, connection: socket.socket, deadline: float) -> None:
        try:
            body = self._read_body(connection, deadline)
            response = OfflineForkRpcReplay.respond(self._replay, body)
        except OfflineForkRpcError:
            self._send(connection, 503, _ERROR_BODY, deadline)
        except (_HttpRequestError, TimeoutError):
            self._send(connection, 400, _ERROR_BODY, deadline)
        else:
            self._send(connection, 200, response, deadline)

    def _serve(self, listener: socket.socket) -> None:
        try:
            while not self._stop_requested.is_set():
                with self._lock:
                    self._failure = self._exhaustion_reason()
                    if self._failure is not None:
                        break
                listener.settimeout(min(_POLL_SECONDS, self._remaining(self._deadline)))
                try:
                    connection, address = listener.accept()
                except TimeoutError:
                    continue
                with self._lock:
                    self._active = connection
                    self._connection_count += 1
                try:
                    if address[0] != "127.0.0.1" or self._stop_requested.is_set():
                        continue
                    request_deadline = min(self._deadline, time.monotonic() + self._timeout_seconds)
                    with suppress(OSError, _HttpRequestError):
                        self._handle(connection, request_deadline)
                finally:
                    _close_connection(connection)
                    with self._lock:
                        self._active = None
        except BaseException:
            with self._lock:
                if not self._stop_requested.is_set():
                    self._failure = "offline lease worker failed"
        finally:
            _close_connection(listener)
            with self._lock:
                self._listener = None
            try:
                OfflineForkRpcReplay.verify_source(self._replay)
            except BaseException:
                with self._lock:
                    self._failure = "offline lease source revalidation failed"
            finally:
                self._finished.set()
