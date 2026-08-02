from __future__ import annotations

import json
import os
import re
import socket
import stat
import threading
import time
from contextlib import suppress
from dataclasses import dataclass, field, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

import httpx
import pytest

from mmaudit.scanners.read_only_rpc import ReadOnlyRpcBridge, ReadOnlyRpcBridgeError

_PINNED_HASH = "0x" + ("ab" * 32)
_ACCOUNT = "0x" + ("11" * 20)


@dataclass
class _OriginState:
    requests: list[object] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


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
        content_length = int(self.headers["Content-Length"])
        request = json.loads(self.rfile.read(content_length))
        with state.lock:
            state.requests.append(request)
        response = _origin_response(request)
        body = json.dumps(response, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _origin_response(payload: object) -> object:
    def one(request: dict[str, object]) -> dict[str, object]:
        method = request["method"]
        if method == "eth_chainId":
            result: object = hex(31_337)
        elif method == "eth_blockNumber":
            result = hex(42)
        elif method in {"eth_getBlockByHash", "eth_getBlockByNumber"}:
            result = {"number": hex(42), "hash": _PINNED_HASH}
        elif method == "eth_getBalance":
            result = "0x1"
        else:
            result = None
        return {"jsonrpc": "2.0", "id": request["id"], "result": result}

    if isinstance(payload, list):
        return [one(cast(dict[str, object], item)) for item in payload]
    return one(cast(dict[str, object], payload))


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


@pytest.fixture
def short_root() -> Path:
    with TemporaryDirectory(prefix="mmaudit-rpc-", dir="/private/tmp") as value:
        root = Path(value)
        root.chmod(0o700)
        yield root


def _private_socket_path(root: Path) -> Path:
    private_directory = root / "control"
    private_directory.mkdir(mode=0o700)
    private_directory.chmod(0o700)
    return private_directory / "readonly-rpc.sock"


def _bridge(origin: str, path: Path) -> ReadOnlyRpcBridge:
    return ReadOnlyRpcBridge(
        origin,
        expected_chain_id=31_337,
        pinned_block_number=42,
        pinned_block_hash=_PINNED_HASH,
        unix_listener_path=path,
    )


def _request(method: str, params: list[object], *, request_id: int = 1) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    }


def _unix_client(path: Path) -> httpx.Client:
    return httpx.Client(
        transport=httpx.HTTPTransport(uds=str(path), retries=0),
        base_url="http://localhost",
        timeout=1,
        trust_env=False,
        follow_redirects=False,
    )


def _ordinary_requests(state: _OriginState) -> list[object]:
    with state.lock:
        requests = list(state.requests)
    return [
        request
        for request in requests
        if isinstance(request, dict) and isinstance(request.get("id"), int)
    ]


def test_owner_only_unix_listener_enforces_read_policy_and_cleans_up(
    local_origin: tuple[str, _OriginState],
    short_root: Path,
) -> None:
    origin, state = local_origin
    path = _private_socket_path(short_root)
    bridge = _bridge(origin, path)

    with pytest.raises(ReadOnlyRpcBridgeError, match="not running"):
        _ = bridge.unix_endpoint_path
    with pytest.raises(ReadOnlyRpcBridgeError, match="not running"):
        _ = bridge.unix_listener_capability_sha256

    bridge.start()
    assert bridge.unix_endpoint_path == path
    assert re.fullmatch(r"[0-9a-f]{64}", bridge.unix_listener_capability_sha256)
    observation = bridge.live_unix_listener_observation()
    with pytest.raises(ValueError, match="observation is invalid"):
        replace(observation, execution_credit=True)  # type: ignore[arg-type]
    endpoint_stat = path.lstat()
    assert stat.S_ISSOCK(endpoint_stat.st_mode)
    assert stat.S_IMODE(endpoint_stat.st_mode) == 0o600
    assert endpoint_stat.st_uid == os.geteuid()
    with pytest.raises(ReadOnlyRpcBridgeError, match="not a TCP endpoint"):
        _ = bridge.endpoint

    with _unix_client(path) as client:
        read_response = client.post(
            "/",
            json=_request("eth_getBalance", [_ACCOUNT, "latest"]),
        )
        write_response = client.post(
            "/",
            json=_request("eth_sendRawTransaction", ["0x00"], request_id=2),
        )

    assert read_response.status_code == 200
    assert read_response.json()["result"] == "0x1"
    assert write_response.status_code == 403
    assert _ordinary_requests(state) == [
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

    bridge.stop()
    assert not path.exists()
    with pytest.raises(ReadOnlyRpcBridgeError, match="not running"):
        _ = bridge.unix_endpoint_path
    with pytest.raises(ReadOnlyRpcBridgeError, match="not running"):
        _ = bridge.unix_listener_capability_sha256
    snapshot = bridge.snapshot()
    assert snapshot.status == "violation"
    assert snapshot.origin_validated_rpc_call_count == 1
    assert snapshot.denied_request_count == 1


@pytest.mark.parametrize("parent_mode", [0o750, 0o707])
def test_unix_listener_rejects_nonprivate_parent(
    local_origin: tuple[str, _OriginState],
    short_root: Path,
    parent_mode: int,
) -> None:
    origin, _state = local_origin
    path = _private_socket_path(short_root)
    path.parent.chmod(parent_mode)

    with pytest.raises(ReadOnlyRpcBridgeError, match="parent identity or mode"):
        _bridge(origin, path)


def test_unix_listener_rejects_symlink_parent(
    local_origin: tuple[str, _OriginState],
    short_root: Path,
) -> None:
    origin, _state = local_origin
    real_parent = short_root / "real"
    real_parent.mkdir(mode=0o700)
    real_parent.chmod(0o700)
    linked_parent = short_root / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ReadOnlyRpcBridgeError, match="must not traverse symlinks"):
        _bridge(origin, linked_parent / "readonly-rpc.sock")


def test_unix_listener_exclusive_creation_rejects_existing_endpoint_and_start_race(
    local_origin: tuple[str, _OriginState],
    short_root: Path,
) -> None:
    origin, _state = local_origin
    path = _private_socket_path(short_root)
    path.write_text("preexisting", encoding="utf-8")
    with pytest.raises(ReadOnlyRpcBridgeError, match="endpoint already exists"):
        _bridge(origin, path)
    assert path.read_text(encoding="utf-8") == "preexisting"

    path.unlink()
    symlink_target = short_root / "target"
    symlink_target.write_text("target", encoding="utf-8")
    path.symlink_to(symlink_target)
    with pytest.raises(ReadOnlyRpcBridgeError, match="endpoint already exists"):
        _bridge(origin, path)
    assert path.is_symlink()
    assert symlink_target.read_text(encoding="utf-8") == "target"

    path.unlink()
    bridge = _bridge(origin, path)
    path.write_text("raced", encoding="utf-8")
    with pytest.raises(ReadOnlyRpcBridgeError, match="could not bind its local listener"):
        bridge.start()
    assert path.read_text(encoding="utf-8") == "raced"


def test_unix_listener_cleanup_refuses_replaced_endpoint(
    local_origin: tuple[str, _OriginState],
    short_root: Path,
) -> None:
    origin, _state = local_origin
    path = _private_socket_path(short_root)
    bridge = _bridge(origin, path)
    bridge.start()

    path.unlink()
    path.write_text("replacement", encoding="utf-8")
    started = time.monotonic()
    with pytest.raises(ReadOnlyRpcBridgeError, match="did not stop cleanly"):
        bridge.stop()
    assert time.monotonic() - started < 2.0

    assert path.read_text(encoding="utf-8") == "replacement"
    with pytest.raises(ReadOnlyRpcBridgeError, match="not running"):
        _ = bridge.unix_endpoint_path
    with pytest.raises(ReadOnlyRpcBridgeError, match="clean stopped bridge"):
        bridge.snapshot()


def test_unix_listener_live_capability_rejects_endpoint_mode_tampering(
    local_origin: tuple[str, _OriginState],
    short_root: Path,
) -> None:
    origin, _state = local_origin
    path = _private_socket_path(short_root)
    bridge = _bridge(origin, path)
    bridge.start()

    path.chmod(0o660)
    with pytest.raises(ReadOnlyRpcBridgeError, match="identity or mode"):
        _ = bridge.unix_listener_capability_sha256
    with pytest.raises(ReadOnlyRpcBridgeError, match="did not stop cleanly"):
        bridge.stop()

    assert stat.S_ISSOCK(path.lstat().st_mode)
    path.unlink()


def test_unix_listener_cleanup_detects_parent_replacement_but_removes_owned_socket(
    local_origin: tuple[str, _OriginState],
    short_root: Path,
) -> None:
    origin, _state = local_origin
    path = _private_socket_path(short_root)
    original_parent = path.parent
    moved_parent = short_root / "moved"
    bridge = _bridge(origin, path)
    bridge.start()

    original_parent.rename(moved_parent)
    original_parent.mkdir(mode=0o700)
    original_parent.chmod(0o700)
    with pytest.raises(ReadOnlyRpcBridgeError, match="did not stop cleanly"):
        bridge.stop()

    assert not (moved_parent / path.name).exists()
    assert list(original_parent.iterdir()) == []


def test_unix_listener_test_scope_remains_fail_closed_without_relay_attestation(
    local_origin: tuple[str, _OriginState],
    short_root: Path,
) -> None:
    origin, _state = local_origin
    path = _private_socket_path(short_root)
    bridge = _bridge(origin, path)
    bridge.start()

    with pytest.raises(ReadOnlyRpcBridgeError, match="relay boundary"):
        bridge.begin_selected_test_scope(
            attempt_binding_sha256="a" * 64,
            selection_sha256="b" * 64,
            descriptor_sha256="c" * 64,
            sequence_index=1,
        )

    bridge.stop()
    assert bridge.snapshot().status == "enforced"


def test_unix_listener_is_af_unix_only(
    local_origin: tuple[str, _OriginState],
    short_root: Path,
) -> None:
    origin, _state = local_origin
    path = _private_socket_path(short_root)
    bridge = _bridge(origin, path)
    bridge.start()

    server = bridge._server
    assert server is not None
    assert server.address_family == socket.AF_UNIX
    assert server.socket.family == socket.AF_UNIX

    bridge.stop()
