from __future__ import annotations

import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass, field, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast
from urllib.parse import urlparse

import httpx
import pytest

from mmaudit.scanners import read_only_rpc as read_only_rpc_module
from mmaudit.scanners.read_only_rpc import (
    ReadOnlyRpcBridge,
    ReadOnlyRpcBridgeError,
    ReadOnlyRpcTestScopeSnapshot,
)

_PINNED_HASH = "0x" + ("ab" * 32)
_ACCOUNT = "0x" + ("11" * 20)
_ATTEMPT_BINDING_SHA256 = "a" * 64
_SELECTION_SHA256 = "b" * 64
_DESCRIPTOR_SHA256 = "c" * 64


@dataclass
class _OriginState:
    requests: list[object] = field(default_factory=list)
    response_body: bytes | None = None
    response_delay_seconds: float = 0
    chain_id: int = 31_337
    block_number: int = 42
    block_hash: str = _PINNED_HASH
    drip_methods: set[str] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)
    request_received: threading.Event = field(default_factory=threading.Event)
    drip_started: threading.Event = field(default_factory=threading.Event)


class _OriginServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    state: _OriginState

    def __init__(self, state: _OriginState) -> None:
        super().__init__(("127.0.0.1", 0), _OriginHandler)
        self.state = state


class _OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self) -> None:
        with suppress(OSError):
            super().handle()

    def do_POST(self) -> None:
        state = cast(_OriginServer, self.server).state
        length = int(self.headers["Content-Length"])
        payload = json.loads(self.rfile.read(length))
        ordinary_request = _has_numeric_request_id(payload)
        with state.lock:
            state.requests.append(payload)
            response_body = state.response_body if ordinary_request else None
            delay = state.response_delay_seconds if ordinary_request else 0
            drip = ordinary_request and bool(_request_methods(payload) & state.drip_methods)
            if ordinary_request:
                state.request_received.set()
        if delay:
            time.sleep(delay)
        if drip:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(1_000_000))
            self.end_headers()
            state.drip_started.set()
            try:
                while True:
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    time.sleep(0.01)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
        if response_body is None:
            response_body = json.dumps(
                _responses_for(payload, state),
                separators=(",", ":"),
            ).encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)
        except BrokenPipeError:
            pass

    def log_message(self, _format: str, *_args: object) -> None:
        return


@pytest.fixture
def local_origin() -> tuple[str, _OriginState]:
    state = _OriginState()
    server = _OriginServer(state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _responses_for(payload: object, state: _OriginState) -> object:
    def one(request: dict[str, object]) -> dict[str, object]:
        method = request["method"]
        if method == "eth_chainId":
            result: object = hex(state.chain_id)
        elif method == "eth_blockNumber":
            result = hex(state.block_number)
        elif method in {"eth_getBlockByHash", "eth_getBlockByNumber"}:
            result = {"number": hex(state.block_number), "hash": state.block_hash}
        elif method == "eth_getBalance":
            result = "0x1"
        elif method in {
            "eth_getBlockTransactionCountByHash",
            "eth_getBlockTransactionCountByNumber",
            "eth_getTransactionCount",
            "eth_getUncleCountByBlockHash",
            "eth_getUncleCountByBlockNumber",
        }:
            result = "0x0"
        elif method in {"eth_call", "eth_getCode"}:
            result = "0x"
        elif method == "eth_getStorageAt":
            result = "0x" + ("00" * 32)
        elif method in {"eth_getBlockReceipts", "eth_getLogs"}:
            result = []
        elif method in {
            "eth_getTransactionByBlockHashAndIndex",
            "eth_getTransactionByBlockNumberAndIndex",
            "eth_getUncleByBlockHashAndIndex",
            "eth_getUncleByBlockNumberAndIndex",
        }:
            result = None
        else:
            result = None
        return {"jsonrpc": "2.0", "id": request["id"], "result": result}

    if isinstance(payload, list):
        return [one(cast(dict[str, object], item)) for item in payload]
    return one(cast(dict[str, object], payload))


def _request_methods(payload: object) -> set[str]:
    items = payload if isinstance(payload, list) else [payload]
    return {
        cast(str, item["method"])
        for item in items
        if isinstance(item, dict) and isinstance(item.get("method"), str)
    }


def _has_numeric_request_id(payload: object) -> bool:
    items = payload if isinstance(payload, list) else [payload]
    return any(isinstance(item, dict) and isinstance(item.get("id"), int) for item in items)


def _ordinary_origin_requests(state: _OriginState) -> list[object]:
    with state.lock:
        requests = list(state.requests)
    ordinary: list[object] = []
    for payload in requests:
        items = payload if isinstance(payload, list) else [payload]
        if _has_numeric_request_id(items):
            ordinary.append(payload)
    return ordinary


def _bridge(endpoint: str, **overrides: object) -> ReadOnlyRpcBridge:
    arguments: dict[str, object] = {
        "expected_chain_id": 31_337,
        "pinned_block_number": 42,
        "pinned_block_hash": _PINNED_HASH,
    }
    arguments.update(overrides)
    return ReadOnlyRpcBridge(endpoint, **arguments)


def _post(endpoint: str, content: bytes) -> httpx.Response:
    return httpx.post(
        endpoint,
        content=content,
        headers={"Content-Type": "application/json"},
        timeout=1,
        trust_env=False,
        follow_redirects=False,
    )


def _queue_raw_post(endpoint: str, content: bytes) -> socket.socket:
    parsed = urlparse(endpoint)
    assert parsed.hostname == "127.0.0.1"
    assert parsed.port is not None
    client = socket.create_connection((parsed.hostname, parsed.port), timeout=1)
    client.sendall(
        b"POST / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(content)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + content
    )
    return client


def _request(method: str, params: list[object], *, request_id: int = 1) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        },
        separators=(",", ":"),
    ).encode()


def _begin_test_scope(
    bridge: ReadOnlyRpcBridge,
    *,
    descriptor_sha256: str = _DESCRIPTOR_SHA256,
    sequence_index: int = 1,
) -> None:
    bridge.begin_selected_test_scope(
        attempt_binding_sha256=_ATTEMPT_BINDING_SHA256,
        selection_sha256=_SELECTION_SHA256,
        descriptor_sha256=descriptor_sha256,
        sequence_index=sequence_index,
    )


def _end_test_scope(
    bridge: ReadOnlyRpcBridge,
    *,
    descriptor_sha256: str = _DESCRIPTOR_SHA256,
    sequence_index: int = 1,
) -> ReadOnlyRpcTestScopeSnapshot:
    return bridge.end_selected_test_scope(
        attempt_binding_sha256=_ATTEMPT_BINDING_SHA256,
        selection_sha256=_SELECTION_SHA256,
        descriptor_sha256=descriptor_sha256,
        sequence_index=sequence_index,
    )


def _wait_for_bridge_handlers(bridge: ReadOnlyRpcBridge) -> None:
    server = bridge._server
    assert server is not None
    assert server.wait_for_handlers(1)


def _wait_for_accept_checkpoint(bridge: ReadOnlyRpcBridge) -> None:
    server = bridge._server
    assert server is not None
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        with server._checkpoint_lock:
            if server._checkpoints_by_source_port:
                return
        time.sleep(0.001)
    raise AssertionError("bridge did not register its accept checkpoint")


def test_bridge_forwards_only_pinned_reads_and_emits_private_self_hashed_snapshot(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin
    bridge = _bridge(origin)

    with bridge:
        bridge_endpoint = bridge.endpoint
        response = _post(
            bridge_endpoint,
            _request("eth_getBalance", [_ACCOUNT, "latest"]),
        )

    assert response.status_code == 200
    assert response.json()["result"] == "0x1"
    assert _ordinary_origin_requests(state) == [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getBalance",
            "params": [
                _ACCOUNT,
                {"blockHash": _PINNED_HASH, "requireCanonical": True},
            ],
        }
    ]
    snapshot = bridge.snapshot()
    assert snapshot.status == "enforced"
    assert snapshot.permitted_rpc_call_count == 1
    assert snapshot.origin_attempted_rpc_call_count == 1
    assert snapshot.origin_validated_rpc_call_count == 1
    assert snapshot.allowed_method_counts == (("eth_getBalance", 1),)
    assert snapshot.verify()
    serialized = json.dumps(snapshot.to_dict(), sort_keys=True)
    assert "127.0.0.1" not in serialized
    assert origin not in serialized
    assert bridge_endpoint not in serialized
    assert _ACCOUNT not in serialized


def test_bridge_canonicalizes_localhost_without_dns_routing(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin
    bridge = _bridge(origin.replace("127.0.0.1", "localhost"))

    with bridge:
        response = _post(
            bridge.endpoint,
            _request("eth_getBalance", [_ACCOUNT, "latest"]),
        )

    assert response.status_code == 200
    assert len(_ordinary_origin_requests(state)) == 1
    assert bridge.snapshot().status == "enforced"


def test_bridge_rejects_entire_mixed_batch_before_forwarding(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin
    mixed_batch = json.dumps(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_getBalance",
                "params": [_ACCOUNT, "latest"],
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "eth_sendRawTransaction",
                "params": ["0x00"],
            },
        ],
        separators=(",", ":"),
    ).encode()
    bridge = _bridge(origin)

    with bridge:
        response = _post(bridge.endpoint, mixed_batch)

    assert response.status_code == 403
    assert _ordinary_origin_requests(state) == []
    snapshot = bridge.snapshot()
    assert snapshot.status == "violation"
    assert snapshot.denied_request_count == 1
    assert snapshot.permitted_rpc_call_count == 0
    assert snapshot.origin_attempted_rpc_call_count == 0
    assert snapshot.origin_validated_rpc_call_count == 0


@pytest.mark.parametrize(
    ("content", "expected_status", "counter"),
    [
        (
            b'{"jsonrpc":"2.0","id":1,"id":2,"method":"eth_chainId","params":[]}',
            400,
            "malformed_request_count",
        ),
        (
            b'{"jsonrpc":"2.0","id":1,"method":"anvil_setBalance","params":[]}',
            403,
            "denied_request_count",
        ),
        (
            b'{"jsonrpc":"2.0","id":1,"method":"eth_unknownRead","params":[]}',
            403,
            "denied_request_count",
        ),
    ],
)
def test_bridge_rejects_duplicate_keys_mutation_names_and_unknown_methods(
    local_origin: tuple[str, _OriginState],
    content: bytes,
    expected_status: int,
    counter: str,
) -> None:
    origin, state = local_origin
    bridge = _bridge(origin)

    with bridge:
        response = _post(bridge.endpoint, content)

    assert response.status_code == expected_status
    assert _ordinary_origin_requests(state) == []
    snapshot = bridge.snapshot()
    assert snapshot.status == "violation"
    assert getattr(snapshot, counter) == 1


def test_bridge_denies_transaction_signing_and_node_mutation_names(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin
    denied_methods = (
        "eth_sendTransaction",
        "eth_sendRawTransaction",
        "eth_sign",
        "personal_sign",
        "admin_nodeInfo",
        "anvil_mine",
        "hardhat_reset",
        "evm_mine",
        "wallet_requestPermissions",
        "debug_traceCall",
        "miner_start",
        "txpool_content",
    )
    bridge = _bridge(origin)

    with bridge:
        responses = [
            _post(
                bridge.endpoint,
                _request(method, ["synthetic-request-canary"], request_id=index),
            )
            for index, method in enumerate(denied_methods, start=1)
        ]

    assert all(response.status_code == 403 for response in responses)
    assert _ordinary_origin_requests(state) == []
    snapshot = bridge.snapshot()
    assert snapshot.denied_request_count == len(denied_methods)
    assert snapshot.permitted_rpc_call_count == 0
    assert "synthetic-request-canary" not in json.dumps(snapshot.to_dict(), sort_keys=True)


def test_bridge_enforces_body_batch_depth_and_aggregate_call_limits(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin

    body_bridge = _bridge(origin, max_request_body_bytes=64)
    with body_bridge:
        body_response = _post(
            body_bridge.endpoint,
            _request("eth_getBalance", [_ACCOUNT, "latest"]),
        )
    assert body_response.status_code == 413
    assert body_bridge.snapshot().limit_exceeded_request_count == 1

    batch_bridge = _bridge(origin, max_batch_size=1)
    with batch_bridge:
        batch_response = _post(
            batch_bridge.endpoint,
            b'[{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]},'
            b'{"jsonrpc":"2.0","id":2,"method":"eth_chainId","params":[]}]',
        )
    assert batch_response.status_code == 413
    assert batch_bridge.snapshot().limit_exceeded_request_count == 1

    depth_bridge = _bridge(origin, max_json_depth=5)
    with depth_bridge:
        depth_response = _post(
            depth_bridge.endpoint,
            _request("eth_call", [{"to": _ACCOUNT, "data": [[[[["0x"]]]]]}, "latest"]),
        )
    assert depth_response.status_code == 413
    assert depth_bridge.snapshot().limit_exceeded_request_count == 1

    call_bridge = _bridge(origin, max_rpc_calls=1)
    with call_bridge:
        first = _post(call_bridge.endpoint, _request("eth_chainId", [], request_id=1))
        second = _post(call_bridge.endpoint, _request("eth_chainId", [], request_id=2))
    assert first.status_code == 200
    assert second.status_code == 413
    assert call_bridge.snapshot().limit_exceeded_request_count == 1
    assert _ordinary_origin_requests(state) == []


@pytest.mark.parametrize(
    "response_body",
    [
        b'{"jsonrpc":"2.0","id":1,"id":2,"result":"0x1"}',
        b'{"jsonrpc":"2.0","id":1,"result":"' + (b"a" * 512) + b'"}',
    ],
)
def test_bridge_rejects_malformed_or_oversized_upstream_responses(
    local_origin: tuple[str, _OriginState],
    response_body: bytes,
) -> None:
    origin, state = local_origin
    state.response_body = response_body
    bridge = _bridge(origin, max_response_body_bytes=256)

    with bridge:
        response = _post(
            bridge.endpoint,
            _request("eth_getBalance", [_ACCOUNT, "latest"]),
        )

    assert response.status_code == 502
    snapshot = bridge.snapshot()
    assert snapshot.status == "violation"
    assert snapshot.upstream_error_request_count == 1
    assert snapshot.origin_attempted_rpc_call_count == 1
    assert snapshot.origin_validated_rpc_call_count == 0


@pytest.mark.parametrize(
    ("method", "params", "result"),
    [
        (
            "eth_getBlockByNumber",
            ["latest", False],
            {"number": "0x29", "hash": _PINNED_HASH},
        ),
        (
            "eth_getBlockByNumber",
            ["latest", False],
            {"number": "0x2a", "hash": "0x" + ("cd" * 32)},
        ),
        (
            "eth_getBlockByHash",
            [_PINNED_HASH, False],
            {"number": "0x2b", "hash": _PINNED_HASH},
        ),
        (
            "eth_getBlockByHash",
            [_PINNED_HASH, False],
            {"number": "0x2a", "hash": "0x" + ("cd" * 32)},
        ),
    ],
)
def test_bridge_rejects_origin_block_results_that_do_not_match_the_exact_pin(
    local_origin: tuple[str, _OriginState],
    method: str,
    params: list[object],
    result: object,
) -> None:
    origin, state = local_origin
    state.response_body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": result},
        separators=(",", ":"),
    ).encode()
    bridge = _bridge(origin)

    with bridge:
        response = _post(bridge.endpoint, _request(method, params))

    assert response.status_code == 502
    snapshot = bridge.snapshot()
    assert snapshot.status == "violation"
    assert snapshot.http_request_count == 1
    assert snapshot.permitted_rpc_call_count == 1
    assert snapshot.origin_attempted_rpc_call_count == 1
    assert snapshot.origin_validated_rpc_call_count == 0
    assert snapshot.synthetic_rpc_call_count == 0
    assert snapshot.upstream_error_request_count == 1
    assert snapshot.allowed_method_counts == ((method, 1),)


@pytest.mark.parametrize(
    ("method", "params"),
    [
        ("eth_getBlockByNumber", ["latest", False]),
        ("eth_getBlockByHash", [_PINNED_HASH, False]),
    ],
)
def test_bridge_accepts_origin_block_results_only_when_number_and_hash_match_pin(
    local_origin: tuple[str, _OriginState],
    method: str,
    params: list[object],
) -> None:
    origin, state = local_origin
    state.response_body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"number": "0x2a", "hash": _PINNED_HASH},
        },
        separators=(",", ":"),
    ).encode()
    bridge = _bridge(origin)

    with bridge:
        response = _post(bridge.endpoint, _request(method, params))

    assert response.status_code == 200
    assert response.json()["result"]["hash"] == _PINNED_HASH
    snapshot = bridge.snapshot()
    assert snapshot.status == "enforced"
    assert snapshot.upstream_error_request_count == 0


def test_bridge_rejects_origin_json_rpc_error_and_preserves_honest_call_counters(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin
    state.response_body = (
        b'[{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"synthetic origin failure"}}]'
    )
    request_body = json.dumps(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "eth_getBalance",
                "params": [_ACCOUNT, "latest"],
            },
        ],
        separators=(",", ":"),
    ).encode()
    bridge = _bridge(origin)

    with bridge:
        response = _post(bridge.endpoint, request_body)

    assert response.status_code == 502
    snapshot = bridge.snapshot()
    assert snapshot.status == "violation"
    assert snapshot.http_request_count == 1
    assert snapshot.permitted_rpc_call_count == 2
    assert snapshot.origin_attempted_rpc_call_count == 1
    assert snapshot.origin_validated_rpc_call_count == 0
    assert snapshot.synthetic_rpc_call_count == 1
    assert snapshot.upstream_error_request_count == 1
    assert snapshot.allowed_method_counts == (
        ("eth_chainId", 1),
        ("eth_getBalance", 1),
    )


def test_bridge_enforces_upstream_timeout_and_stops_cleanly(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin
    state.response_delay_seconds = 0.1
    bridge = _bridge(origin, timeout_seconds=0.01)

    with bridge:
        endpoint = bridge.endpoint
        response = _post(
            endpoint,
            _request("eth_getBalance", [_ACCOUNT, "latest"]),
        )

    assert response.status_code == 502
    assert bridge.snapshot().upstream_error_request_count == 1
    with pytest.raises(httpx.ConnectError):
        _post(endpoint, _request("eth_chainId", []))


def test_bridge_shutdown_is_absolute_bounded_during_a_slow_drip_request(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, _state = local_origin
    bridge = _bridge(origin, timeout_seconds=0.5)
    bridge.start()
    parsed_endpoint = urlparse(bridge.endpoint)
    assert parsed_endpoint.hostname == "127.0.0.1"
    assert parsed_endpoint.port is not None
    client = socket.create_connection((parsed_endpoint.hostname, parsed_endpoint.port), timeout=1)
    client.sendall(
        b"POST / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 4096\r\n"
        b"Connection: close\r\n\r\n{"
    )
    stop_drip = threading.Event()

    def drip_request_body() -> None:
        while not stop_drip.wait(0.02):
            try:
                client.sendall(b" ")
            except OSError:
                return

    drip_thread = threading.Thread(target=drip_request_body, daemon=True)
    drip_thread.start()
    # Give the server time to enter its bounded request-body read.
    time.sleep(0.05)
    delayed_cleanup = threading.Timer(0.75, client.close)
    delayed_cleanup.start()
    started = time.monotonic()
    try:
        bridge.stop()
    finally:
        elapsed = time.monotonic() - started
        stop_drip.set()
        with suppress(OSError):
            client.close()
        drip_thread.join(timeout=1)
        delayed_cleanup.cancel()

    assert elapsed < 0.4
    snapshot = bridge.snapshot()
    assert snapshot.stopped_cleanly is True
    assert snapshot.http_request_count == 1
    assert snapshot.malformed_request_count == 1


def test_bridge_shutdown_fails_closed_when_a_handler_cannot_drain(
    local_origin: tuple[str, _OriginState],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin, _state = local_origin
    entered_forward = threading.Event()
    release_forward = threading.Event()
    bridge = _bridge(
        origin,
        timeout_seconds=0.5,
        shutdown_timeout_seconds=0.1,
    )

    def stuck_forward(
        _outbound_body: bytes,
        _outbound_calls: list[object],
        *,
        is_batch: bool,
    ) -> dict[object, object]:
        del is_batch
        entered_forward.set()
        release_forward.wait(timeout=2)
        raise RuntimeError("synthetic stuck handler")

    monkeypatch.setattr(bridge, "_forward", stuck_forward)
    bridge.start()
    with ThreadPoolExecutor(max_workers=1) as executor:
        request_future = executor.submit(
            _post,
            bridge.endpoint,
            _request("eth_getBalance", [_ACCOUNT, "latest"]),
        )
        assert entered_forward.wait(timeout=1)
        started = time.monotonic()
        try:
            with pytest.raises(ReadOnlyRpcBridgeError, match="absolute bound"):
                bridge.stop()
        finally:
            elapsed = time.monotonic() - started
            release_forward.set()
        with suppress(httpx.HTTPError):
            request_future.result(timeout=1)

    assert elapsed < 0.3
    with pytest.raises(ReadOnlyRpcBridgeError, match="clean stopped bridge"):
        bridge.snapshot()
    with pytest.raises(ReadOnlyRpcBridgeError, match="already attempted"):
        bridge.stop()
    with pytest.raises(ReadOnlyRpcBridgeError, match="not running"):
        _ = bridge.endpoint


def test_bridge_bounds_concurrent_handlers_before_forwarding(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin
    state.response_delay_seconds = 0.15
    bridge = _bridge(origin, max_concurrent_handlers=1, timeout_seconds=0.5)

    with bridge, ThreadPoolExecutor(max_workers=1) as executor:
        first_future = executor.submit(
            _post,
            bridge.endpoint,
            _request("eth_getBalance", [_ACCOUNT, "latest"], request_id=1),
        )
        assert state.request_received.wait(timeout=1)
        second = _post(
            bridge.endpoint,
            _request("eth_getBalance", [_ACCOUNT, "latest"], request_id=2),
        )
        first = first_future.result(timeout=1)

    assert first.status_code == 200
    assert second.status_code == 503
    assert len(_ordinary_origin_requests(state)) == 1
    snapshot = bridge.snapshot()
    assert snapshot.status == "violation"
    assert snapshot.limit_exceeded_request_count == 1
    assert snapshot.origin_attempted_rpc_call_count == 1
    assert snapshot.origin_validated_rpc_call_count == 1


def test_bridge_drops_sensitive_inbound_headers_without_retaining_canary(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin
    canary = "synthetic-control-secret-canary"
    bridge = _bridge(origin)

    with bridge:
        response = httpx.post(
            bridge.endpoint,
            content=_request("eth_chainId", []),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {canary}",
            },
            timeout=1,
            trust_env=False,
            follow_redirects=False,
        )

    assert response.status_code == 403
    assert _ordinary_origin_requests(state) == []
    serialized = json.dumps(bridge.snapshot().to_dict(), sort_keys=True)
    assert canary not in serialized
    assert "authorization" not in serialized.lower()


@pytest.mark.parametrize(
    "origin",
    [
        "https://127.0.0.1:8545",
        "http://example.invalid:8545",
        "http://user:password@127.0.0.1:8545",
        "http://127.0.0.1:8545/rpc",
        "http://127.0.0.1:8545/?token=secret",
    ],
)
def test_bridge_rejects_non_exact_or_credentialed_origin(origin: str) -> None:
    with pytest.raises(ReadOnlyRpcBridgeError):
        _bridge(origin)


@pytest.mark.parametrize(
    "overrides",
    [
        {"expected_chain_id": True},
        {"pinned_block_number": False},
    ],
)
def test_bridge_rejects_boolean_chain_and_block_identities(
    local_origin: tuple[str, _OriginState],
    overrides: dict[str, object],
) -> None:
    origin, _state = local_origin
    arguments: dict[str, object] = {
        "expected_chain_id": 31_337,
        "pinned_block_number": 42,
        "pinned_block_hash": _PINNED_HASH,
    }
    arguments.update(overrides)
    with pytest.raises(ReadOnlyRpcBridgeError, match="state identity"):
        ReadOnlyRpcBridge(origin, **arguments)


def test_bridge_preflight_rejects_wrong_origin_chain_before_binding_listener(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin
    bridge = _bridge(origin, expected_chain_id=1)
    try:
        with pytest.raises(ReadOnlyRpcBridgeError, match="origin identity preflight"):
            bridge.start()
    finally:
        if bridge._started and not bridge._stop_attempted:
            bridge.stop()

    assert _ordinary_origin_requests(state) == []
    with pytest.raises(ReadOnlyRpcBridgeError, match="not running"):
        _ = bridge.endpoint
    with pytest.raises(ReadOnlyRpcBridgeError, match="clean stopped bridge"):
        bridge.snapshot()


@pytest.mark.parametrize(
    ("state_field", "value"),
    [
        ("block_number", 43),
        ("block_hash", "0x" + ("cd" * 32)),
    ],
)
def test_bridge_preflight_rejects_wrong_origin_block_identity_before_listener(
    local_origin: tuple[str, _OriginState],
    state_field: str,
    value: object,
) -> None:
    origin, state = local_origin
    setattr(state, state_field, value)
    bridge = _bridge(origin)

    with pytest.raises(ReadOnlyRpcBridgeError, match="origin identity preflight"):
        bridge.start()

    with pytest.raises(ReadOnlyRpcBridgeError, match="not running"):
        _ = bridge.endpoint


def test_empty_bridge_snapshot_binds_stable_pre_and_post_origin_identity(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, _state = local_origin
    bridge = _bridge(origin)

    with bridge:
        pass

    snapshot = bridge.snapshot()
    assert snapshot.status == "enforced"
    assert snapshot.permitted_rpc_call_count == 0
    assert snapshot.origin_attempted_rpc_call_count == 0
    assert snapshot.origin_validated_rpc_call_count == 0
    assert snapshot.synthetic_rpc_call_count == 0
    assert snapshot.origin_state_stable is True
    assert snapshot.preflight_origin_observation_sha256 == (
        snapshot.postflight_origin_observation_sha256
    )
    assert len(snapshot.preflight_origin_observation_sha256) == 64
    assert snapshot.selected_test_scope_snapshot_sha256s == ()
    assert "selected_test_scope_snapshot_sha256s" not in snapshot.to_dict()
    assert snapshot.verify()


def test_bridge_postflight_rejects_origin_identity_drift_and_cannot_seal(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin
    bridge = _bridge(origin)
    bridge.start()
    with state.lock:
        state.block_hash = "0x" + ("cd" * 32)

    with pytest.raises(ReadOnlyRpcBridgeError, match="origin identity postflight"):
        bridge.stop()

    with pytest.raises(ReadOnlyRpcBridgeError, match="clean stopped bridge"):
        bridge.snapshot()


@pytest.mark.parametrize(
    ("method", "params", "block_parameter_index"),
    [
        ("eth_call", [{"to": _ACCOUNT, "data": "0x"}, "latest"], 1),
        ("eth_getBalance", [_ACCOUNT, "latest"], 1),
        ("eth_getCode", [_ACCOUNT, "latest"], 1),
        ("eth_getStorageAt", [_ACCOUNT, "0x0", "latest"], 2),
        ("eth_getTransactionCount", [_ACCOUNT, "latest"], 1),
    ],
)
def test_bridge_hash_binds_eip_1898_state_reads(
    local_origin: tuple[str, _OriginState],
    method: str,
    params: list[object],
    block_parameter_index: int,
) -> None:
    origin, state = local_origin
    bridge = _bridge(origin)

    with bridge:
        response = _post(bridge.endpoint, _request(method, params))

    assert response.status_code == 200
    ordinary = _ordinary_origin_requests(state)
    assert len(ordinary) == 1
    forwarded = cast(dict[str, object], ordinary[0])
    forwarded_params = cast(list[object], forwarded["params"])
    assert forwarded_params[block_parameter_index] == {
        "blockHash": _PINNED_HASH,
        "requireCanonical": True,
    }


def test_bridge_accepts_only_exact_canonical_eip_1898_reference(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin
    bridge = _bridge(origin)

    with bridge:
        accepted = _post(
            bridge.endpoint,
            _request(
                "eth_getBalance",
                [
                    _ACCOUNT,
                    {"blockHash": _PINNED_HASH, "requireCanonical": True},
                ],
                request_id=1,
            ),
        )
        rejected = _post(
            bridge.endpoint,
            _request(
                "eth_getBalance",
                [
                    _ACCOUNT,
                    {"blockHash": _PINNED_HASH, "requireCanonical": False},
                ],
                request_id=2,
            ),
        )

    assert accepted.status_code == 200
    assert rejected.status_code == 403
    assert len(_ordinary_origin_requests(state)) == 1


@pytest.mark.parametrize(
    ("method", "params", "forwarded_method", "forwarded_params"),
    [
        (
            "eth_getBlockByNumber",
            ["latest", False],
            "eth_getBlockByHash",
            [_PINNED_HASH, False],
        ),
        (
            "eth_getBlockTransactionCountByNumber",
            ["latest"],
            "eth_getBlockTransactionCountByHash",
            [_PINNED_HASH],
        ),
        (
            "eth_getTransactionByBlockNumberAndIndex",
            ["latest", "0x0"],
            "eth_getTransactionByBlockHashAndIndex",
            [_PINNED_HASH, "0x0"],
        ),
        (
            "eth_getUncleByBlockNumberAndIndex",
            ["latest", "0x0"],
            "eth_getUncleByBlockHashAndIndex",
            [_PINNED_HASH, "0x0"],
        ),
        (
            "eth_getUncleCountByBlockNumber",
            ["latest"],
            "eth_getUncleCountByBlockHash",
            [_PINNED_HASH],
        ),
    ],
)
def test_bridge_rewrites_number_named_reads_to_exact_hash_equivalents(
    local_origin: tuple[str, _OriginState],
    method: str,
    params: list[object],
    forwarded_method: str,
    forwarded_params: list[object],
) -> None:
    origin, state = local_origin
    bridge = _bridge(origin)

    with bridge:
        response = _post(bridge.endpoint, _request(method, params))

    assert response.status_code == 200
    ordinary = _ordinary_origin_requests(state)
    assert ordinary == [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": forwarded_method,
            "params": forwarded_params,
        }
    ]


def test_bridge_denies_read_method_that_cannot_be_hash_bound(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin
    bridge = _bridge(origin)

    with bridge:
        response = _post(
            bridge.endpoint,
            _request("eth_feeHistory", ["0x1", "latest", []]),
        )

    assert response.status_code == 403
    assert _ordinary_origin_requests(state) == []
    snapshot = bridge.snapshot()
    assert snapshot.denied_request_count == 1
    assert snapshot.permitted_rpc_call_count == 0


@pytest.mark.parametrize(
    ("method", "params", "result"),
    [
        (
            "eth_getLogs",
            [{"fromBlock": "latest", "toBlock": "latest"}],
            [{"blockNumber": "0x2a", "blockHash": "0x" + ("cd" * 32)}],
        ),
        (
            "eth_getBlockReceipts",
            ["latest"],
            [{"blockNumber": "0x2b", "blockHash": _PINNED_HASH}],
        ),
        (
            "eth_getTransactionByBlockHashAndIndex",
            [_PINNED_HASH, "0x0"],
            {"blockNumber": "0x2a", "blockHash": "0x" + ("cd" * 32)},
        ),
    ],
)
def test_bridge_rejects_result_provenance_outside_the_pinned_block(
    local_origin: tuple[str, _OriginState],
    method: str,
    params: list[object],
    result: object,
) -> None:
    origin, state = local_origin
    state.response_body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": result},
        separators=(",", ":"),
    ).encode()
    bridge = _bridge(origin)

    with bridge:
        response = _post(bridge.endpoint, _request(method, params))

    assert response.status_code == 502
    snapshot = bridge.snapshot()
    assert snapshot.origin_attempted_rpc_call_count == 1
    assert snapshot.origin_validated_rpc_call_count == 0
    assert snapshot.upstream_error_request_count == 1


@pytest.mark.parametrize(
    ("method", "params", "result"),
    [
        ("eth_getBalance", [_ACCOUNT, "latest"], "1"),
        ("eth_call", [{"to": _ACCOUNT, "data": "0x"}, "latest"], "0x0"),
        ("eth_getCode", [_ACCOUNT, "latest"], "0xGG"),
        ("eth_getStorageAt", [_ACCOUNT, "0x0", "latest"], "0x00"),
        (
            "eth_getUncleByBlockHashAndIndex",
            [_PINNED_HASH, "0x0"],
            {"number": "42", "hash": "0x" + ("cd" * 32)},
        ),
    ],
)
def test_bridge_rejects_invalid_result_shape_for_each_retained_method_family(
    local_origin: tuple[str, _OriginState],
    method: str,
    params: list[object],
    result: object,
) -> None:
    origin, state = local_origin
    state.response_body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": result},
        separators=(",", ":"),
    ).encode()
    bridge = _bridge(origin)

    with bridge:
        response = _post(bridge.endpoint, _request(method, params))

    assert response.status_code == 502
    snapshot = bridge.snapshot()
    assert snapshot.origin_attempted_rpc_call_count == 1
    assert snapshot.origin_validated_rpc_call_count == 0
    assert snapshot.upstream_error_request_count == 1


def test_bridge_http_admission_hard_saturates_at_configured_maximum(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, _state = local_origin
    bridge = _bridge(origin, max_http_requests=1)
    bridge.start()
    endpoint = bridge.endpoint

    first = _post(endpoint, _request("eth_chainId", []))
    assert first.status_code == 200
    deadline = time.monotonic() + 1
    while True:
        try:
            _post(endpoint, _request("eth_chainId", []))
        except httpx.HTTPError:
            break
        if time.monotonic() >= deadline:
            pytest.fail("bridge listener remained open after HTTP admission saturated")
    bridge.stop()

    snapshot = bridge.snapshot()
    assert snapshot.http_request_count == 1
    assert snapshot.permitted_rpc_call_count == 1
    assert snapshot.synthetic_rpc_call_count == 1


def test_bridge_cancels_indefinitely_slow_origin_stream_without_thread_or_listener_leak(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin
    bridge = _bridge(
        origin,
        timeout_seconds=0.5,
        shutdown_timeout_seconds=0.5,
    )
    bridge.start()
    endpoint = bridge.endpoint
    with state.lock:
        state.drip_methods.add("eth_getBalance")

    with ThreadPoolExecutor(max_workers=1) as executor:
        request_future = executor.submit(
            _post,
            endpoint,
            _request("eth_getBalance", [_ACCOUNT, "latest"]),
        )
        assert state.drip_started.wait(timeout=1)
        started = time.monotonic()
        bridge.stop()
        elapsed = time.monotonic() - started
        with suppress(httpx.HTTPError):
            request_future.result(timeout=1)

    assert elapsed < 0.5
    assert not [
        thread.name
        for thread in threading.enumerate()
        if thread.name.startswith("mmaudit-read-only-rpc")
    ]
    with pytest.raises(httpx.ConnectError):
        _post(endpoint, _request("eth_chainId", []))
    snapshot = bridge.snapshot()
    assert snapshot.origin_attempted_rpc_call_count == 1
    assert snapshot.origin_validated_rpc_call_count == 0
    assert snapshot.upstream_error_request_count == 1


def test_selected_test_scope_seals_exact_endpoint_free_accounting(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, _state = local_origin
    bridge = _bridge(origin)
    bridge.start()
    endpoint = bridge.endpoint
    _begin_test_scope(bridge)

    origin_response = _post(
        endpoint,
        _request("eth_getBalance", [_ACCOUNT, "latest"], request_id=1),
    )
    synthetic_response = _post(
        endpoint,
        _request("eth_chainId", [], request_id=2),
    )
    _wait_for_bridge_handlers(bridge)
    scope = _end_test_scope(bridge)
    bridge.stop()

    assert origin_response.status_code == 200
    assert synthetic_response.status_code == 200
    assert scope.schema_version == "1.0"
    assert scope.status == "validated"
    assert scope.attempt_binding_sha256 == _ATTEMPT_BINDING_SHA256
    assert scope.selection_sha256 == _SELECTION_SHA256
    assert scope.descriptor_sha256 == _DESCRIPTOR_SHA256
    assert scope.sequence_index == 1
    assert scope.expected_chain_id == 31_337
    assert scope.pinned_block_number == 42
    assert scope.pinned_block_hash == _PINNED_HASH
    assert scope.http_request_count == 2
    assert scope.permitted_rpc_call_count == 2
    assert scope.origin_attempted_rpc_call_count == 1
    assert scope.origin_validated_rpc_call_count == 1
    assert scope.synthetic_rpc_call_count == 1
    assert scope.denied_request_count == 0
    assert scope.malformed_request_count == 0
    assert scope.limit_exceeded_request_count == 0
    assert scope.upstream_error_request_count == 0
    assert scope.allowed_method_counts == (
        ("eth_chainId", 1),
        ("eth_getBalance", 1),
    )
    assert scope.boundary_drained is True
    assert scope.verify()
    serialized = json.dumps(scope.to_dict(), sort_keys=True)
    assert origin not in serialized
    assert endpoint not in serialized
    assert _ACCOUNT not in serialized
    aggregate = bridge.snapshot()
    assert aggregate.http_request_count == scope.http_request_count
    assert aggregate.permitted_rpc_call_count == scope.permitted_rpc_call_count
    assert aggregate.selected_test_scope_snapshot_sha256s == (scope.snapshot_sha256,)


def test_selected_test_scope_marks_synthetic_only_observation_not_observed(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, _state = local_origin
    bridge = _bridge(origin)
    bridge.start()
    _begin_test_scope(bridge)

    response = _post(bridge.endpoint, _request("eth_chainId", []))
    _wait_for_bridge_handlers(bridge)
    scope = _end_test_scope(bridge)
    bridge.stop()

    assert response.status_code == 200
    assert scope.status == "not_observed"
    assert scope.http_request_count == 1
    assert scope.permitted_rpc_call_count == 1
    assert scope.origin_attempted_rpc_call_count == 0
    assert scope.origin_validated_rpc_call_count == 0
    assert scope.synthetic_rpc_call_count == 1


def test_selected_test_scope_marks_any_request_error_as_violation(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin
    bridge = _bridge(origin)
    bridge.start()
    _begin_test_scope(bridge)

    denied = _post(
        bridge.endpoint,
        _request("eth_sendRawTransaction", ["0x00"], request_id=1),
    )
    malformed = _post(bridge.endpoint, b"{}")
    _wait_for_bridge_handlers(bridge)
    scope = _end_test_scope(bridge)
    bridge.stop()

    assert denied.status_code == 403
    assert malformed.status_code == 400
    assert _ordinary_origin_requests(state) == []
    assert scope.status == "violation"
    assert scope.http_request_count == 2
    assert scope.permitted_rpc_call_count == 0
    assert scope.denied_request_count == 1
    assert scope.malformed_request_count == 1
    assert scope.limit_exceeded_request_count == 0
    assert scope.upstream_error_request_count == 0


def test_selected_test_scope_rejects_overlap_wrong_identity_and_invalid_lifecycle(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, _state = local_origin
    bridge = _bridge(origin)
    with pytest.raises(ReadOnlyRpcBridgeError, match="not running"):
        _begin_test_scope(bridge)

    bridge.start()
    _begin_test_scope(bridge)
    with pytest.raises(ReadOnlyRpcBridgeError, match="cannot overlap"):
        _begin_test_scope(
            bridge,
            descriptor_sha256="d" * 64,
            sequence_index=2,
        )
    with pytest.raises(ReadOnlyRpcBridgeError, match="identity does not match"):
        _end_test_scope(
            bridge,
            descriptor_sha256="d" * 64,
            sequence_index=2,
        )

    scope = _end_test_scope(bridge)
    assert scope.status == "not_observed"
    with pytest.raises(ReadOnlyRpcBridgeError, match="not active"):
        _end_test_scope(bridge)
    with pytest.raises(TypeError):
        bridge.begin_selected_test_scope(  # type: ignore[call-arg]
            attempt_binding_sha256=_ATTEMPT_BINDING_SHA256,
            selection_sha256=_SELECTION_SHA256,
            descriptor_sha256=_DESCRIPTOR_SHA256,
        )
    bridge.stop()
    with pytest.raises(ReadOnlyRpcBridgeError, match="not running"):
        _begin_test_scope(bridge, descriptor_sha256="d" * 64, sequence_index=2)
    with pytest.raises(ReadOnlyRpcBridgeError, match="not running"):
        _end_test_scope(bridge, descriptor_sha256="d" * 64, sequence_index=2)


@pytest.mark.parametrize("sequence_index", [0, 10_001, True])
def test_selected_test_scope_requires_one_based_bounded_sequence_identity(
    local_origin: tuple[str, _OriginState],
    sequence_index: int,
) -> None:
    origin, _state = local_origin
    bridge = _bridge(origin)
    bridge.start()
    try:
        with pytest.raises(ReadOnlyRpcBridgeError, match="identity is invalid"):
            _begin_test_scope(bridge, sequence_index=sequence_index)
    finally:
        bridge.stop()


def test_selected_test_scope_boundaries_wait_for_active_handlers_within_bound(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, state = local_origin
    state.response_delay_seconds = 0.15
    bridge = _bridge(origin, timeout_seconds=0.5)
    bridge.start()

    with ThreadPoolExecutor(max_workers=1) as executor:
        unscoped_future = executor.submit(
            _post,
            bridge.endpoint,
            _request("eth_getBalance", [_ACCOUNT, "latest"], request_id=1),
        )
        assert state.request_received.wait(timeout=1)
        started = time.monotonic()
        _begin_test_scope(bridge)
        begin_elapsed = time.monotonic() - started
        assert unscoped_future.result(timeout=1).status_code == 200

        state.request_received.clear()
        scoped_future = executor.submit(
            _post,
            bridge.endpoint,
            _request("eth_getBalance", [_ACCOUNT, "latest"], request_id=2),
        )
        assert state.request_received.wait(timeout=1)
        started = time.monotonic()
        scope = _end_test_scope(bridge)
        end_elapsed = time.monotonic() - started
        assert scoped_future.result(timeout=1).status_code == 200

    bridge.stop()
    assert begin_elapsed >= 0.05
    assert end_elapsed >= 0.05
    assert scope.status == "validated"
    assert scope.http_request_count == 1
    assert scope.origin_attempted_rpc_call_count == 1
    assert scope.origin_validated_rpc_call_count == 1


def test_selected_test_scope_begin_drains_connection_queued_before_checkpoint(
    local_origin: tuple[str, _OriginState],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin, _state = local_origin
    accept_waiting = threading.Event()
    release_accept = threading.Event()
    original_get_request = read_only_rpc_module._BridgeHttpServer.get_request

    def held_get_request(
        server: read_only_rpc_module._BridgeHttpServer,
    ) -> tuple[socket.socket, object]:
        accept_waiting.set()
        if not release_accept.wait(timeout=1):
            raise RuntimeError("synthetic accept gate timed out")
        return original_get_request(server)

    monkeypatch.setattr(
        read_only_rpc_module._BridgeHttpServer,
        "get_request",
        held_get_request,
    )
    bridge = _bridge(origin)
    bridge.start()
    client = _queue_raw_post(
        bridge.endpoint,
        _request("eth_getBalance", [_ACCOUNT, "latest"]),
    )
    try:
        assert accept_waiting.wait(timeout=1)
        with ThreadPoolExecutor(max_workers=1) as executor:
            begin_future = executor.submit(_begin_test_scope, bridge)
            _wait_for_accept_checkpoint(bridge)
            assert not begin_future.done()
            release_accept.set()
            begin_future.result(timeout=1)
        scope = _end_test_scope(bridge)
        bridge.stop()
    finally:
        client.close()

    assert scope.status == "not_observed"
    assert scope.http_request_count == 0
    aggregate = bridge.snapshot()
    assert aggregate.http_request_count == 1
    assert aggregate.origin_validated_rpc_call_count == 1


def test_selected_test_scope_end_includes_connection_queued_before_checkpoint(
    local_origin: tuple[str, _OriginState],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin, _state = local_origin
    second_accept_waiting = threading.Event()
    release_second_accept = threading.Event()
    call_count = 0
    call_count_lock = threading.Lock()
    original_get_request = read_only_rpc_module._BridgeHttpServer.get_request

    def gate_second_get_request(
        server: read_only_rpc_module._BridgeHttpServer,
    ) -> tuple[socket.socket, object]:
        nonlocal call_count
        with call_count_lock:
            call_count += 1
            current_call = call_count
        if current_call == 2:
            second_accept_waiting.set()
            if not release_second_accept.wait(timeout=1):
                raise RuntimeError("synthetic accept gate timed out")
        return original_get_request(server)

    monkeypatch.setattr(
        read_only_rpc_module._BridgeHttpServer,
        "get_request",
        gate_second_get_request,
    )
    bridge = _bridge(origin)
    bridge.start()
    _begin_test_scope(bridge)
    client = _queue_raw_post(
        bridge.endpoint,
        _request("eth_getBalance", [_ACCOUNT, "latest"]),
    )
    try:
        assert second_accept_waiting.wait(timeout=1)
        with ThreadPoolExecutor(max_workers=1) as executor:
            end_future = executor.submit(_end_test_scope, bridge)
            _wait_for_accept_checkpoint(bridge)
            assert not end_future.done()
            release_second_accept.set()
            scope = end_future.result(timeout=1)
        bridge.stop()
    finally:
        client.close()

    assert scope.status == "validated"
    assert scope.http_request_count == 1
    assert scope.origin_attempted_rpc_call_count == 1
    assert scope.origin_validated_rpc_call_count == 1


def test_selected_test_scope_end_waits_after_response_until_handler_finishes(
    local_origin: tuple[str, _OriginState],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin, _state = local_origin
    finish_entered = threading.Event()
    release_finish = threading.Event()
    original_finish_handler = read_only_rpc_module._BridgeHttpServer._finish_handler

    def held_finish_handler(
        server: read_only_rpc_module._BridgeHttpServer,
        request: socket.socket,
    ) -> None:
        finish_entered.set()
        if not release_finish.wait(timeout=1):
            raise RuntimeError("synthetic handler-finalization gate timed out")
        original_finish_handler(server, request)

    monkeypatch.setattr(
        read_only_rpc_module._BridgeHttpServer,
        "_finish_handler",
        held_finish_handler,
    )
    bridge = _bridge(origin)
    bridge.start()
    _begin_test_scope(bridge)
    server = bridge._server
    assert server is not None
    checkpoint_accepted = threading.Event()
    original_accept_checkpoint = server.accept_boundary_checkpoint

    def observed_accept_checkpoint(
        timeout_seconds: float,
    ) -> read_only_rpc_module._AcceptBoundaryCheckpoint:
        checkpoint = original_accept_checkpoint(timeout_seconds)
        checkpoint_accepted.set()
        return checkpoint

    monkeypatch.setattr(server, "accept_boundary_checkpoint", observed_accept_checkpoint)

    with ThreadPoolExecutor(max_workers=2) as executor:
        request_future = executor.submit(
            _post,
            bridge.endpoint,
            _request("eth_getBalance", [_ACCOUNT, "latest"]),
        )
        assert finish_entered.wait(timeout=1)
        assert request_future.result(timeout=1).status_code == 200
        end_future = executor.submit(_end_test_scope, bridge)
        assert checkpoint_accepted.wait(timeout=1)
        assert not end_future.done()
        release_finish.set()
        scope = end_future.result(timeout=1)

    bridge.stop()
    assert scope.status == "validated"
    assert scope.boundary_drained is True
    assert scope.origin_validated_rpc_call_count == 1


def test_abandoned_selected_test_scope_shutdown_cleans_resources_and_fails_closed(
    local_origin: tuple[str, _OriginState],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin, _state = local_origin
    finish_entered = threading.Event()
    release_finish = threading.Event()
    original_finish_handler = read_only_rpc_module._BridgeHttpServer._finish_handler

    def held_finish_handler(
        server: read_only_rpc_module._BridgeHttpServer,
        request: socket.socket,
    ) -> None:
        finish_entered.set()
        release_finish.wait(timeout=1)
        original_finish_handler(server, request)

    monkeypatch.setattr(
        read_only_rpc_module._BridgeHttpServer,
        "_finish_handler",
        held_finish_handler,
    )
    bridge = _bridge(
        origin,
        timeout_seconds=0.5,
        shutdown_timeout_seconds=0.2,
    )
    bridge.start()
    endpoint = bridge.endpoint
    _begin_test_scope(bridge)

    with ThreadPoolExecutor(max_workers=1) as executor:
        request_future = executor.submit(
            _post,
            endpoint,
            _request("eth_getBalance", [_ACCOUNT, "latest"]),
        )
        assert finish_entered.wait(timeout=1)
        with pytest.raises(ReadOnlyRpcBridgeError, match="boundary exceeded"):
            _end_test_scope(bridge)
        release_finish.set()
        assert request_future.result(timeout=1).status_code == 200
        _wait_for_bridge_handlers(bridge)
        with pytest.raises(ReadOnlyRpcBridgeError, match="scope was abandoned"):
            bridge.stop()

    server = bridge._server
    assert server is not None
    assert server.handlers_drained()
    assert bridge._upstream_resources_drained()
    assert bridge._active_test_scope is None
    with pytest.raises(httpx.ConnectError):
        _post(endpoint, _request("eth_chainId", []))
    with pytest.raises(ReadOnlyRpcBridgeError, match="clean stopped bridge"):
        bridge.snapshot()
    with pytest.raises(ReadOnlyRpcBridgeError, match="already attempted"):
        bridge.stop()
    with pytest.raises(ReadOnlyRpcBridgeError, match="not running"):
        _end_test_scope(bridge)


def test_selected_test_scope_rejects_hash_and_count_tampering(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, _state = local_origin
    bridge = _bridge(origin)
    bridge.start()
    _begin_test_scope(bridge)
    response = _post(bridge.endpoint, _request("eth_chainId", []))
    _wait_for_bridge_handlers(bridge)
    scope = _end_test_scope(bridge)
    bridge.stop()

    assert response.status_code == 200
    with pytest.raises(ValueError, match="hash is inconsistent"):
        replace(scope, snapshot_sha256="f" * 64)
    with pytest.raises(ValueError, match="inconsistent"):
        replace(scope, permitted_rpc_call_count=2)


def test_bridge_snapshot_binds_ordered_unique_sealed_scope_ledger(
    local_origin: tuple[str, _OriginState],
) -> None:
    origin, _state = local_origin
    bridge = _bridge(origin)
    bridge.start()

    _begin_test_scope(bridge)
    first = _end_test_scope(bridge)
    _begin_test_scope(
        bridge,
        descriptor_sha256="d" * 64,
        sequence_index=2,
    )
    second = _end_test_scope(
        bridge,
        descriptor_sha256="d" * 64,
        sequence_index=2,
    )
    bridge.stop()

    snapshot = bridge.snapshot()
    assert snapshot.selected_test_scope_snapshot_sha256s == (
        first.snapshot_sha256,
        second.snapshot_sha256,
    )
    assert snapshot.verify()
    with pytest.raises(ValueError, match="hash is inconsistent"):
        replace(
            snapshot,
            selected_test_scope_snapshot_sha256s=(
                second.snapshot_sha256,
                first.snapshot_sha256,
            ),
        )
    with pytest.raises(ValueError, match="inconsistent"):
        replace(
            snapshot,
            selected_test_scope_snapshot_sha256s=(
                first.snapshot_sha256,
                first.snapshot_sha256,
            ),
        )
