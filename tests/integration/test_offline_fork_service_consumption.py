"""Owned loopback lease consumption and scoped bridge; no chain, engine or external origin."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import subprocess
import threading
import time
from contextlib import suppress

import httpx
import pytest

from mmaudit.scanners.fork_rpc import local_fork_rpc_port, observe_pinned_fork_rpc
from mmaudit.scanners.offline_fork_rpc import OfflineForkRpcReplay, load_offline_fork_rpc_archive
from mmaudit.scanners.offline_fork_service import OfflineForkRpcLease, OfflineForkRpcLeaseError
from mmaudit.scanners.read_only_rpc import ReadOnlyRpcBridge
from tests.unit.test_offline_fork_rpc import ADDRESS, BLOCK_HASH, FIXTURE, _request


@pytest.fixture(autouse=True)
def owned_loopback_only(monkeypatch):
    original_socket = socket.socket
    original_resolve = socket.getaddrinfo
    owned_ports = set()

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: offline read transport cannot execute or access external services")

    class OwnedSocket(original_socket):
        def bind(self, address):
            assert self.family == socket.AF_INET
            assert address == ("127.0.0.1", 0)
            result = super().bind(address)
            owned_ports.add(self.getsockname()[1])
            return result

        def connect(self, address):
            assert self.family == socket.AF_INET
            assert address[0] == "127.0.0.1" and address[1] in owned_ports
            return super().connect(address)

        def connect_ex(self, address):
            assert self.family == socket.AF_INET
            assert address[0] == "127.0.0.1" and address[1] in owned_ports
            return super().connect_ex(address)

    def numeric_resolution(host, port, family=0, type=0, proto=0, flags=0):
        assert host in {"127.0.0.1", b"127.0.0.1"}
        assert int(port) in owned_ports
        return original_resolve(host, port, family, type, proto, flags | socket.AI_NUMERICHOST)

    monkeypatch.setattr(socket, "socket", OwnedSocket)
    monkeypatch.setattr(socket, "getaddrinfo", numeric_resolution)
    monkeypatch.setattr(socket, "getfqdn", lambda name="": "localhost")
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "gethostbyaddr", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    return owned_ports


@pytest.fixture
def lease_factory(tmp_path, owned_loopback_only):
    root = tmp_path.resolve(strict=True)
    source = root / "reads.json"
    shutil.copyfile(FIXTURE, source)
    leases = []

    def create(**kwargs):
        replay = load_offline_fork_rpc_archive(
            root,
            source.name,
            expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            expected_chain_id=31337,
            pinned_block_number=7,
        )
        lease = OfflineForkRpcLease(replay, **kwargs)
        leases.append(lease)
        return lease

    yield source, create
    for lease in leases:
        with suppress(OfflineForkRpcLeaseError):
            lease.stop()
        assert lease._worker is None or not lease._worker.is_alive()
        assert lease._listener is None
        assert lease._active is None


def _post(client, endpoint, method, params):
    return client.post(
        endpoint,
        content=_request(method, params),
        headers={"Content-Type": "application/json"},
    )


def _raw(endpoint, content):
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(2)
    connection.connect(("127.0.0.1", local_fork_rpc_port(endpoint)))
    connection.sendall(content)
    return connection


def _wait_for_active(lease):
    deadline = time.monotonic() + 1
    while lease._active is None and time.monotonic() < deadline:
        time.sleep(0.005)
    assert lease._active is not None


@pytest.mark.parametrize("repeat", [False, True])
def test_actual_loopback_client_reads_exact_frozen_data_and_closes(lease_factory, repeat):
    source, create = lease_factory
    original = source.read_bytes()
    lease = create()
    with lease, httpx.Client(trust_env=False, timeout=2) as client:
        endpoint = lease.endpoint
        for _ in range(2 if repeat else 1):
            observed = observe_pinned_fork_rpc(
                endpoint, expected_chain_id=31337, pinned_block_number=7, client=client
            )
            assert observed == lease.observation
            response = _post(client, endpoint, "eth_getBalance", [ADDRESS, "0x7"])
            assert response.status_code == 200
            assert response.json()["result"] == "0x5"
            assert response.headers["connection"] == "close"
        assert lease.complete_state is lease.runtime_authority is False
        with pytest.raises(OfflineForkRpcLeaseError):
            lease.start()
    assert lease.stopped_cleanly is True
    lease.stop()
    assert source.read_bytes() == original
    assert list(source.parent.iterdir()) == [source]
    with pytest.raises(OfflineForkRpcLeaseError):
        _ = lease.endpoint
    with (
        pytest.raises(OSError),
        socket.create_connection(("127.0.0.1", local_fork_rpc_port(endpoint)), timeout=0.1),
    ):
        pytest.fail("invariant: closed lease cannot accept further reads")


@pytest.mark.parametrize("method", ["eth_getCode", "eth_sendRawTransaction"])
def test_unavailable_and_mutating_requests_cannot_return_zero_or_contact_an_origin(
    lease_factory, method
):
    _, create = lease_factory
    with create() as lease, httpx.Client(trust_env=False, timeout=2) as client:
        response = _post(client, lease.endpoint, method, [ADDRESS, "0x7"])
        assert response.status_code == 503
        assert "result" not in response.json()
        assert ADDRESS not in response.text
        assert _post(client, lease.endpoint, "eth_chainId", []).json()["result"] == "0x7a69"
    assert lease.stopped_cleanly


@pytest.mark.parametrize("missing", [False, True])
def test_unchanged_scoped_bridge_consumes_archive_without_promoting_a_chain(lease_factory, missing):
    _, create = lease_factory
    scope_identity = {
        "attempt_binding_sha256": "a" * 64,
        "selection_sha256": "c" * 64,
        "descriptor_sha256": "d" * 64,
        "sequence_index": 1,
    }
    with create() as lease:
        bridge = ReadOnlyRpcBridge(
            lease.endpoint,
            expected_chain_id=31337,
            pinned_block_number=7,
            pinned_block_hash=BLOCK_HASH,
            timeout_seconds=1,
        )
        with bridge, httpx.Client(trust_env=False, timeout=2) as client:
            bridge.begin_selected_test_scope(**scope_identity)
            response = _post(
                client,
                bridge.endpoint,
                "eth_getCode" if missing else "eth_getBalance",
                [ADDRESS, "0x7"],
            )
            scope = bridge.end_selected_test_scope(**scope_identity)
        assert scope.verify()
        assert scope.status == ("violation" if missing else "validated")
        assert scope.origin_attempted_rpc_call_count == 1
        assert scope.origin_validated_rpc_call_count == (0 if missing else 1)
        assert response.status_code == (502 if missing else 200)
        assert bridge.snapshot().verify()
        # This is only transport/read accounting, not real state or execution evidence.
        assert lease.runtime_authority is lease.complete_state is False
    assert lease.stopped_cleanly


def test_archive_drift_after_start_cannot_produce_a_clean_stop(lease_factory):
    source, create = lease_factory
    lease = create()
    lease.start()
    with httpx.Client(trust_env=False, timeout=2) as client:
        source.write_text("{}")
        assert (
            _post(client, lease.endpoint, "eth_getBalance", [ADDRESS, "0x7"]).json()["result"]
            == "0x5"
        )
    with pytest.raises(OfflineForkRpcLeaseError):
        lease.stop()
    assert lease.stopped_cleanly is False
    with pytest.raises(OfflineForkRpcLeaseError):
        lease.stop()


def test_idle_lease_expires_and_closes_without_operator_cleanup(lease_factory):
    _, create = lease_factory
    lease = create(lifetime_seconds=0.1)
    lease.start()
    assert lease._finished.wait(2)
    with pytest.raises(OfflineForkRpcLeaseError):
        _ = lease.endpoint
    with pytest.raises(OfflineForkRpcLeaseError):
        lease.stop()
    assert lease.stopped_cleanly is False


def test_malformed_connections_consume_the_hard_admission_budget(lease_factory):
    _, create = lease_factory
    lease = create(max_connections=1)
    lease.start()
    with _raw(lease.endpoint, b"GET / HTTP/1.1\r\n\r\n") as connection:
        assert b"400 Bad Request" in connection.recv(4096)
    assert lease._finished.wait(2)
    assert lease._connection_count == 1
    with pytest.raises(OfflineForkRpcLeaseError):
        lease.stop()


def test_absolute_request_deadline_prevents_trickle_input_from_holding_the_worker(lease_factory):
    _, create = lease_factory
    lease = create(timeout_seconds=0.1)
    with lease:
        start = time.monotonic()
        with _raw(lease.endpoint, b"POST ") as connection:
            _wait_for_active(lease)
            for _ in range(20):
                time.sleep(0.03)
                with suppress(OSError):
                    connection.sendall(b" ")
                if lease._active is None:
                    break
            assert time.monotonic() - start < 0.6
            assert lease._active is None
        with httpx.Client(trust_env=False, timeout=2) as client:
            assert _post(client, lease.endpoint, "eth_chainId", []).status_code == 200


def test_stop_interrupts_an_incomplete_request_within_caller_deadline(lease_factory):
    _, create = lease_factory
    lease = create(timeout_seconds=5)
    lease.start()
    with _raw(lease.endpoint, b"POST / HTTP/1.1\r\n") as connection:
        _wait_for_active(lease)
        start = time.monotonic()
        lease.stop(deadline=start + 1)
        assert time.monotonic() - start < 1
        with suppress(OSError):
            assert connection.recv(4096) == b""
    assert lease.stopped_cleanly


def test_aggregate_byte_budget_refuses_before_publishing_an_oversize_response(lease_factory):
    source, create = lease_factory
    archive = json.loads(source.read_bytes())
    archive["reads"].append(
        {
            "method": "eth_getCode",
            "params": archive["reads"][1]["params"],
            "result": "0x" + "00" * 1024,
        }
    )
    source.write_text(json.dumps(archive))
    lease = create(max_total_bytes=1024)
    lease.start()
    with (
        httpx.Client(trust_env=False, timeout=2) as client,
        pytest.raises(httpx.RemoteProtocolError),
    ):
        _post(client, lease.endpoint, "eth_getCode", [ADDRESS, "0x7"])
    assert lease._finished.wait(2)
    assert lease._byte_count == 1024
    with pytest.raises(OfflineForkRpcLeaseError):
        lease.stop()


@pytest.mark.parametrize("deadline_offset", [0, -(10**1000)], ids=["current", "oversized-past"])
def test_expired_shutdown_deadline_closes_but_never_claims_clean_success(
    lease_factory, deadline_offset
):
    _, create = lease_factory
    lease = create()
    lease.start()
    deadline = time.monotonic() if deadline_offset == 0 else deadline_offset
    with pytest.raises(OfflineForkRpcLeaseError):
        lease.stop(deadline=deadline)
    assert lease._finished.wait(2)
    assert lease.stopped_cleanly is False


def test_postflight_verification_cannot_make_shutdown_unbounded(lease_factory, monkeypatch):
    _, create = lease_factory
    original = OfflineForkRpcReplay.verify_source
    entered = threading.Event()
    release = threading.Event()
    lease = create()
    lease.start()

    def paused_verification(replay):
        entered.set()
        assert release.wait(2)
        return original(replay)

    monkeypatch.setattr(OfflineForkRpcReplay, "verify_source", paused_verification)
    start = time.monotonic()
    try:
        with pytest.raises(OfflineForkRpcLeaseError):
            lease.stop(deadline=start + 0.1)
        assert time.monotonic() - start < 0.5
        assert entered.is_set()
        assert lease.stopped_cleanly is False
    finally:
        release.set()
        assert lease._finished.wait(2)
    with pytest.raises(OfflineForkRpcLeaseError):
        lease.stop()


def test_shutdown_lock_timeout_is_sticky_and_cannot_later_become_a_clean_result(lease_factory):
    _, create = lease_factory
    lease = create()
    lease.start()
    with lease._lock, pytest.raises(OfflineForkRpcLeaseError):
        lease.stop(deadline=time.monotonic() + 0.05)
    assert lease._finished.wait(2)
    with pytest.raises(OfflineForkRpcLeaseError):
        lease.stop()
    assert lease.stopped_cleanly is False


def test_stop_cannot_race_expiry_into_a_clean_result(lease_factory):
    _, create = lease_factory
    lease = create()
    lease.start()
    # Hold only the trusted control-plane boundary; no request handler or fake read result.
    with lease._lock:
        lease._deadline = time.monotonic() - 1
        lease._stop_requested.set()
    assert lease._finished.wait(2)
    with pytest.raises(OfflineForkRpcLeaseError):
        lease.stop()
    assert lease.stopped_cleanly is False


def test_one_worker_bounds_simultaneous_accepted_connections(lease_factory):
    _, create = lease_factory
    lease = create(timeout_seconds=5)
    lease.start()
    endpoint = lease.endpoint
    with _raw(endpoint, b"POST "), _raw(endpoint, b"POST "):
        _wait_for_active(lease)
        assert lease._connection_count == 1
        workers = [
            thread
            for thread in threading.enumerate()
            if thread.name == "mmaudit-offline-fork-reads"
        ]
        assert workers == [lease._worker]
        lease.stop()
    assert lease.stopped_cleanly


@pytest.mark.parametrize("extra", [b"trailing", b"POST / HTTP/1.1\r\n\r\n"])
def test_extra_or_pipelined_payloads_are_not_dispatched_as_additional_reads(lease_factory, extra):
    _, create = lease_factory
    with create() as lease:
        host = lease.endpoint.removeprefix("http://")
        request = (
            (
                f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n"
                "Content-Length: 2\r\n\r\n"
            ).encode()
            + b"{}"
            + extra
        )
        with _raw(lease.endpoint, request) as connection:
            assert b"400 Bad Request" in connection.recv(4096)
        assert lease._replay._request_count == 0
