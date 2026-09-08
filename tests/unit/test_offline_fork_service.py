"""Offline read-service controls never bind sockets or execute tools in unit tests."""

from __future__ import annotations

import copy
import hashlib
import pickle
import shutil
import socket
import subprocess
import time

import pytest

from mmaudit.scanners.offline_fork_rpc import load_offline_fork_rpc_archive
from mmaudit.scanners.offline_fork_service import (
    OfflineForkRpcLease,
    OfflineForkRpcLeaseError,
    _HttpRequestError,
    _parse_http_head,
)
from tests.unit.test_offline_fork_rpc import FIXTURE


@pytest.fixture(autouse=True)
def no_network_or_tools(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: unit controls cannot bind, connect, resolve or execute")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)


@pytest.fixture
def archive(tmp_path):
    root = tmp_path.resolve(strict=True)
    source = root / "reads.json"
    shutil.copyfile(FIXTURE, source)
    replay = load_offline_fork_rpc_archive(
        root,
        source.name,
        expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        expected_chain_id=31337,
        pinned_block_number=7,
    )
    return source, replay


def _head(**changes):
    headers = {
        "Host": "127.0.0.1:12345",
        "Content-Type": "application/json",
        "Content-Length": "2",
    }
    headers.update(changes)
    return (
        "POST / HTTP/1.1\r\n"
        + "\r\n".join(f"{name}: {value}" for name, value in headers.items())
        + "\r\n\r\n"
    ).encode("ascii")


def test_unstarted_lease_has_no_endpoint_or_authority(archive):
    lease = OfflineForkRpcLease(archive[1])
    assert lease.runtime_authority is lease.complete_state is lease.stopped_cleanly is False
    assert lease.observation == archive[1].observation
    assert lease.source_binding == archive[1].source_binding
    assert lease.source_binding is not archive[1].source_binding
    with pytest.raises(OfflineForkRpcLeaseError):
        _ = lease.endpoint
    with pytest.raises(OfflineForkRpcLeaseError):
        lease.stop()


@pytest.mark.parametrize("value", [None, object(), {}, "http://127.0.0.1:12345"])
def test_only_admitted_replay_type_can_be_served(value):
    with pytest.raises(OfflineForkRpcLeaseError):
        OfflineForkRpcLease(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("timeout_seconds", 0),
        ("timeout_seconds", True),
        ("timeout_seconds", 6),
        ("timeout_seconds", float("nan")),
        pytest.param("timeout_seconds", 10**1000, id="timeout-oversized-integer"),
        ("lifetime_seconds", 0),
        ("lifetime_seconds", True),
        ("lifetime_seconds", 3601),
        ("lifetime_seconds", float("inf")),
        pytest.param("lifetime_seconds", 10**1000, id="lifetime-oversized-integer"),
        ("max_connections", 0),
        ("max_connections", True),
        ("max_connections", 10001),
        ("max_connections", 1.5),
        ("max_total_bytes", 1023),
        ("max_total_bytes", True),
        ("max_total_bytes", 64 * 1024 * 1024 + 1),
    ],
)
def test_service_limits_cannot_be_unbounded_or_coerced(archive, field, value):
    with pytest.raises(OfflineForkRpcLeaseError):
        OfflineForkRpcLease(archive[1], **{field: value})


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_live_resource_handles_cannot_be_copied_or_serialized(archive, operation):
    with pytest.raises(TypeError):
        operation(OfflineForkRpcLease(archive[1]))


def test_source_drift_refuses_before_opening_any_listener(archive):
    source, replay = archive
    lease = OfflineForkRpcLease(replay)
    source.write_text("{}")
    with pytest.raises(OfflineForkRpcLeaseError):
        lease.start()
    with pytest.raises(OfflineForkRpcLeaseError):
        lease.start()
    assert lease.stopped_cleanly is False


@pytest.mark.parametrize("protocol", [b"HTTP/1.0", b"HTTP/1.1"])
def test_http_framing_accepts_only_explicit_local_json_reads(protocol):
    head = _head(**{"Connection": "keep-alive", "Accept-Encoding": "gzip, deflate"})
    assert _parse_http_head(head.replace(b"HTTP/1.1", protocol), "127.0.0.1:12345") == 2


@pytest.mark.parametrize(
    "head",
    [
        _head().replace(b"POST", b"GET", 1),
        _head().replace(b"POST / ", b"POST /other ", 1),
        _head().replace(b"POST / ", b"POST http://127.0.0.1:12345/ ", 1),
        _head().replace(b"HTTP/1.1", b"HTTP/2.0"),
        _head().replace(b"\r\n", b"\n"),
        _head().replace(b"Content-Length: 2", b"Content-Length: 2\r\ncontent-length: 2"),
        _head(**{"Host": "localhost:12345"}),
        _head(**{"Host": "127.0.0.1:54321"}),
        _head(**{"Content-Length": "02"}),
        _head(**{"Content-Length": "+2"}),
        _head(**{"Content-Length": "1048577"}),
        _head(**{"Content-Length": "0"}),
        _head(**{"Content-Type": "text/plain"}),
        _head(**{"Transfer-Encoding": "chunked"}),
        _head(**{"Content-Encoding": "gzip"}),
        _head(**{"Authorization": "synthetic-not-a-credential"}),
        _head(**{"Cookie": "synthetic=value"}),
        _head(**{"Origin": "null"}),
        _head(**{"Expect": "100-continue"}),
        _head(**{"Upgrade": "websocket"}),
        _head(**{"User-Agent": "x\r\n folded"}),
        _head(**{"User-Agent": "x\x00y"}),
        _head(**{"User-Agent": "x" * 16384}),
        _head().replace(b"Host: 127.0.0.1:12345\r\n", b""),
    ],
)
def test_ambiguous_or_nonlocal_http_requests_refuse_without_echo(head):
    with pytest.raises(_HttpRequestError) as error:
        _parse_http_head(head, "127.0.0.1:12345")
    assert "synthetic" not in str(error.value)
    assert "12345" not in str(error.value)


@pytest.mark.parametrize("stage", ["bind", "listen", "settimeout", "thread"])
def test_partial_listener_startup_closes_owned_resource(archive, monkeypatch, stage):
    import threading

    class Listener:
        closed = False

        def bind(self, address):
            assert address == ("127.0.0.1", 0)
            if stage == "bind":
                raise OSError

        def listen(self, backlog):
            assert backlog == 8
            if stage == "listen":
                raise OSError

        def settimeout(self, seconds):
            assert 0 < seconds <= 0.05
            if stage == "settimeout":
                raise OSError

        def getsockname(self):
            return "127.0.0.1", 12345

        def shutdown(self, how):
            pass

        def close(self):
            self.closed = True

    listener = Listener()
    monkeypatch.setattr(socket, "socket", lambda *args: listener)

    def fail_start(self):
        raise RuntimeError

    monkeypatch.setattr(threading.Thread, "start", fail_start)
    lease = OfflineForkRpcLease(archive[1])
    with pytest.raises(OfflineForkRpcLeaseError):
        lease.start()
    assert listener.closed
    assert lease.stopped_cleanly is False
    with pytest.raises(OfflineForkRpcLeaseError):
        _ = lease.endpoint


@pytest.mark.parametrize("deadline", [True, "later", float("nan"), float("inf"), float("-inf")])
def test_invalid_shutdown_deadline_refuses_without_coercion(archive, deadline):
    with pytest.raises(OfflineForkRpcLeaseError, match="deadline"):
        OfflineForkRpcLease(archive[1]).stop(deadline=deadline)


def test_received_bytes_cannot_overshoot_the_remaining_traffic_budget(archive):
    lease = OfflineForkRpcLease(archive[1], max_total_bytes=1024)
    lease._byte_count = 1020

    class Connection:
        def __init__(self):
            self.requested = []

        def settimeout(self, value):
            assert 0 < value <= 1

        def recv(self, size):
            self.requested.append(size)
            return b"x" * size

    connection = Connection()
    deadline = time.monotonic() + 1
    assert lease._receive(connection, 4096, deadline) == b"xxxx"
    with pytest.raises(_HttpRequestError):
        lease._receive(connection, 4096, deadline)
    assert connection.requested == [4]
    assert lease._byte_count == 1024
