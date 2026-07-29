"""Trusted bounded read-only JSON-RPC bridge for repository fork execution.

The bridge exposes only a fixed Ethereum read vocabulary on an ephemeral loopback
listener. It never forwards caller headers, unknown methods, signing requests, or
state-changing RPC methods. Its immutable final snapshot contains counters and
hashes only: no endpoint, request body, parameter, response body, or port.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import socket
import threading
import time
from contextlib import suppress
from dataclasses import dataclass, field
from enum import StrEnum
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Literal, cast
from urllib.parse import urlparse

from mmaudit.scanners.fork_rpc import ForkRpcBindingError, local_fork_rpc_port

_POLICY_VERSION = "MMAUDIT_READ_ONLY_RPC_BRIDGE_V2"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_BLOCK_HASH_PATTERN = re.compile(r"^0x[0-9a-f]{64}$")
_BLOCK_TAG_PATTERN = re.compile(r"^0x(?:0|[1-9a-f][0-9a-f]*)$")
_DEFAULT_MAX_REQUEST_BODY_BYTES = 1_048_576
_DEFAULT_MAX_RESPONSE_BODY_BYTES = 8_388_608
_DEFAULT_MAX_BATCH_SIZE = 100
_DEFAULT_MAX_JSON_DEPTH = 32
_DEFAULT_MAX_JSON_NODES = 100_000
_DEFAULT_MAX_HTTP_REQUESTS = 10_000
_DEFAULT_MAX_RPC_CALLS = 100_000
_DEFAULT_MAX_CONCURRENT_HANDLERS = 16
_DEFAULT_SHUTDOWN_TIMEOUT_SECONDS = 1.0
_MAX_REQUEST_BODY_BYTES = 8_388_608
_MAX_RESPONSE_BODY_BYTES = 67_108_864
_MAX_BATCH_SIZE = 1_000
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 1_000_000
_MAX_HTTP_REQUESTS = 1_000_000
_MAX_RPC_CALLS = 1_000_000
_MAX_CONCURRENT_HANDLERS = 256
_MAX_SHUTDOWN_TIMEOUT_SECONDS = 10.0
_MAX_RPC_ID_TEXT_LENGTH = 128
_MAX_RPC_PARAMS = 64
_MAX_TIMEOUT_SECONDS = 60.0
_MAX_IDENTITY_RESPONSE_BODY_BYTES = 65_536
_PINNED_SYMBOLIC_TAGS = frozenset({"latest", "safe", "finalized"})
_SENSITIVE_INBOUND_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
    }
)

# Every method not present here is denied before an origin request is created.
# The retained vocabulary is deliberately narrow: each forwarded read is either
# EIP-1898 hash-bound or has a semantically equivalent hash-named RPC method.
_METHOD_ARITY: dict[str, tuple[int, int]] = {
    "eth_blockNumber": (0, 0),
    "eth_call": (1, 2),
    "eth_chainId": (0, 0),
    "eth_getBalance": (2, 2),
    "eth_getBlockByHash": (2, 2),
    "eth_getBlockByNumber": (2, 2),
    "eth_getBlockReceipts": (1, 1),
    "eth_getBlockTransactionCountByHash": (1, 1),
    "eth_getBlockTransactionCountByNumber": (1, 1),
    "eth_getCode": (2, 2),
    "eth_getLogs": (1, 1),
    "eth_getStorageAt": (3, 3),
    "eth_getTransactionByBlockHashAndIndex": (2, 2),
    "eth_getTransactionByBlockNumberAndIndex": (2, 2),
    "eth_getTransactionCount": (2, 2),
    "eth_getUncleByBlockHashAndIndex": (2, 2),
    "eth_getUncleByBlockNumberAndIndex": (2, 2),
    "eth_getUncleCountByBlockHash": (1, 1),
    "eth_getUncleCountByBlockNumber": (1, 1),
    "net_version": (0, 0),
}
_ALLOWED_METHODS = frozenset(_METHOD_ARITY)
_SYNTHETIC_METHODS = frozenset({"eth_blockNumber", "eth_chainId", "net_version"})
_EIP_1898_PARAM_INDEX: dict[str, int] = {
    "eth_call": 1,
    "eth_getBalance": 1,
    "eth_getCode": 1,
    "eth_getStorageAt": 2,
    "eth_getTransactionCount": 1,
}
_HASH_PARAM_INDEX: dict[str, int] = {
    "eth_getBlockByHash": 0,
    "eth_getBlockTransactionCountByHash": 0,
    "eth_getTransactionByBlockHashAndIndex": 0,
    "eth_getUncleByBlockHashAndIndex": 0,
    "eth_getUncleCountByBlockHash": 0,
}
_NUMBER_TO_HASH_METHOD: dict[str, str] = {
    "eth_getBlockByNumber": "eth_getBlockByHash",
    "eth_getBlockTransactionCountByNumber": "eth_getBlockTransactionCountByHash",
    "eth_getTransactionByBlockNumberAndIndex": "eth_getTransactionByBlockHashAndIndex",
    "eth_getUncleByBlockNumberAndIndex": "eth_getUncleByBlockHashAndIndex",
    "eth_getUncleCountByBlockNumber": "eth_getUncleCountByBlockHash",
}
_QUANTITY_RESULT_METHODS = frozenset(
    {
        "eth_getBalance",
        "eth_getBlockTransactionCountByHash",
        "eth_getBlockTransactionCountByNumber",
        "eth_getTransactionCount",
        "eth_getUncleCountByBlockHash",
        "eth_getUncleCountByBlockNumber",
    }
)
_BYTE_RESULT_METHODS = frozenset({"eth_call", "eth_getCode"})


class ReadOnlyRpcBridgeError(RuntimeError):
    """The read-only bridge could not be configured or operated safely."""


@dataclass(frozen=True)
class ReadOnlyRpcBridgeSnapshot:
    """Endpoint-free immutable summary of one stopped bridge."""

    schema_version: Literal["2.0"]
    status: Literal["enforced", "violation"]
    policy_sha256: str
    expected_chain_id: int
    pinned_block_number: int
    pinned_block_hash: str
    preflight_origin_observation_sha256: str
    postflight_origin_observation_sha256: str
    origin_state_stable: Literal[True]
    http_request_count: int
    permitted_rpc_call_count: int
    origin_attempted_rpc_call_count: int
    origin_validated_rpc_call_count: int
    synthetic_rpc_call_count: int
    denied_request_count: int
    malformed_request_count: int
    limit_exceeded_request_count: int
    upstream_error_request_count: int
    allowed_method_counts: tuple[tuple[str, int], ...]
    method_log_sha256: str
    stopped_cleanly: Literal[True]
    snapshot_sha256: str
    selected_test_scope_snapshot_sha256s: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        violation_count = (
            self.denied_request_count
            + self.malformed_request_count
            + self.limit_exceeded_request_count
            + self.upstream_error_request_count
        )
        if (
            self.schema_version != "2.0"
            or not _SHA256_PATTERN.fullmatch(self.policy_sha256)
            or not _SHA256_PATTERN.fullmatch(self.preflight_origin_observation_sha256)
            or not _SHA256_PATTERN.fullmatch(self.postflight_origin_observation_sha256)
            or not _SHA256_PATTERN.fullmatch(self.method_log_sha256)
            or not _SHA256_PATTERN.fullmatch(self.snapshot_sha256)
            or any(
                not isinstance(scope_sha256, str) or _SHA256_PATTERN.fullmatch(scope_sha256) is None
                for scope_sha256 in self.selected_test_scope_snapshot_sha256s
            )
            or len(self.selected_test_scope_snapshot_sha256s)
            != len(set(self.selected_test_scope_snapshot_sha256s))
            or type(self.expected_chain_id) is not int
            or self.expected_chain_id < 1
            or self.expected_chain_id >= 2**64
            or type(self.pinned_block_number) is not int
            or self.pinned_block_number < 0
            or self.pinned_block_number >= 2**64
            or not _BLOCK_HASH_PATTERN.fullmatch(self.pinned_block_hash)
            or self.preflight_origin_observation_sha256 != self.postflight_origin_observation_sha256
            or self.origin_state_stable is not True
            or any(
                type(count) is not int or count < 0
                for count in (
                    self.http_request_count,
                    self.permitted_rpc_call_count,
                    self.origin_attempted_rpc_call_count,
                    self.origin_validated_rpc_call_count,
                    self.synthetic_rpc_call_count,
                    self.denied_request_count,
                    self.malformed_request_count,
                    self.limit_exceeded_request_count,
                    self.upstream_error_request_count,
                )
            )
            or self.origin_attempted_rpc_call_count + self.synthetic_rpc_call_count
            != self.permitted_rpc_call_count
            or self.origin_validated_rpc_call_count > self.origin_attempted_rpc_call_count
            or (self.origin_validated_rpc_call_count == self.origin_attempted_rpc_call_count)
            != (self.upstream_error_request_count == 0)
            or self.allowed_method_counts
            != tuple(sorted(self.allowed_method_counts, key=lambda item: item[0]))
            or len({method for method, _count in self.allowed_method_counts})
            != len(self.allowed_method_counts)
            or any(
                method not in _ALLOWED_METHODS or type(count) is not int or count < 1
                for method, count in self.allowed_method_counts
            )
            or sum(count for _method, count in self.allowed_method_counts)
            != self.permitted_rpc_call_count
            or violation_count > self.http_request_count
            or self.status != ("violation" if violation_count else "enforced")
            or self.stopped_cleanly is not True
        ):
            raise ValueError("read-only RPC bridge snapshot is inconsistent")
        if not self.verify():
            raise ValueError("read-only RPC bridge snapshot hash is inconsistent")

    def to_dict(self, *, include_snapshot_sha256: bool = True) -> dict[str, object]:
        """Return the endpoint-free canonical primitive projection."""

        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "status": self.status,
            "policy_sha256": self.policy_sha256,
            "expected_chain_id": self.expected_chain_id,
            "pinned_block_number": self.pinned_block_number,
            "pinned_block_hash": self.pinned_block_hash,
            "preflight_origin_observation_sha256": self.preflight_origin_observation_sha256,
            "postflight_origin_observation_sha256": self.postflight_origin_observation_sha256,
            "origin_state_stable": self.origin_state_stable,
            "http_request_count": self.http_request_count,
            "permitted_rpc_call_count": self.permitted_rpc_call_count,
            "origin_attempted_rpc_call_count": self.origin_attempted_rpc_call_count,
            "origin_validated_rpc_call_count": self.origin_validated_rpc_call_count,
            "synthetic_rpc_call_count": self.synthetic_rpc_call_count,
            "denied_request_count": self.denied_request_count,
            "malformed_request_count": self.malformed_request_count,
            "limit_exceeded_request_count": self.limit_exceeded_request_count,
            "upstream_error_request_count": self.upstream_error_request_count,
            "allowed_method_counts": [
                {"method": method, "count": count} for method, count in self.allowed_method_counts
            ],
            "method_log_sha256": self.method_log_sha256,
            "stopped_cleanly": self.stopped_cleanly,
        }
        if self.selected_test_scope_snapshot_sha256s:
            result["selected_test_scope_snapshot_sha256s"] = list(
                self.selected_test_scope_snapshot_sha256s
            )
        if include_snapshot_sha256:
            result["snapshot_sha256"] = self.snapshot_sha256
        return result

    def verify(self) -> bool:
        """Verify the snapshot's self-hash without reading external state."""

        return self.snapshot_sha256 == _canonical_sha256(
            self.to_dict(include_snapshot_sha256=False)
        )


@dataclass(frozen=True)
class ReadOnlyRpcTestScopeSnapshot:
    """Endpoint-free immutable accounting for one selected test descriptor."""

    schema_version: Literal["1.0"]
    attempt_binding_sha256: str
    selection_sha256: str
    descriptor_sha256: str
    sequence_index: int
    policy_sha256: str
    expected_chain_id: int
    pinned_block_number: int
    pinned_block_hash: str
    status: Literal["validated", "not_observed", "violation"]
    http_request_count: int
    permitted_rpc_call_count: int
    origin_attempted_rpc_call_count: int
    origin_validated_rpc_call_count: int
    synthetic_rpc_call_count: int
    denied_request_count: int
    malformed_request_count: int
    limit_exceeded_request_count: int
    upstream_error_request_count: int
    allowed_method_counts: tuple[tuple[str, int], ...]
    method_log_sha256: str
    boundary_drained: Literal[True]
    snapshot_sha256: str

    def __post_init__(self) -> None:
        violation_count = (
            self.denied_request_count
            + self.malformed_request_count
            + self.limit_exceeded_request_count
            + self.upstream_error_request_count
        )
        expected_status: Literal["validated", "not_observed", "violation"]
        if violation_count or (
            self.origin_validated_rpc_call_count != self.origin_attempted_rpc_call_count
        ):
            expected_status = "violation"
        elif self.origin_attempted_rpc_call_count:
            expected_status = "validated"
        else:
            expected_status = "not_observed"
        if (
            self.schema_version != "1.0"
            or not _SHA256_PATTERN.fullmatch(self.attempt_binding_sha256)
            or not _SHA256_PATTERN.fullmatch(self.selection_sha256)
            or not _SHA256_PATTERN.fullmatch(self.descriptor_sha256)
            or not _SHA256_PATTERN.fullmatch(self.policy_sha256)
            or not _SHA256_PATTERN.fullmatch(self.method_log_sha256)
            or not _SHA256_PATTERN.fullmatch(self.snapshot_sha256)
            or type(self.sequence_index) is not int
            or not 1 <= self.sequence_index <= 10_000
            or type(self.expected_chain_id) is not int
            or self.expected_chain_id < 1
            or self.expected_chain_id >= 2**64
            or type(self.pinned_block_number) is not int
            or self.pinned_block_number < 0
            or self.pinned_block_number >= 2**64
            or not _BLOCK_HASH_PATTERN.fullmatch(self.pinned_block_hash)
            or any(
                type(count) is not int or count < 0
                for count in (
                    self.http_request_count,
                    self.permitted_rpc_call_count,
                    self.origin_attempted_rpc_call_count,
                    self.origin_validated_rpc_call_count,
                    self.synthetic_rpc_call_count,
                    self.denied_request_count,
                    self.malformed_request_count,
                    self.limit_exceeded_request_count,
                    self.upstream_error_request_count,
                )
            )
            or self.origin_attempted_rpc_call_count + self.synthetic_rpc_call_count
            != self.permitted_rpc_call_count
            or self.origin_validated_rpc_call_count > self.origin_attempted_rpc_call_count
            or self.allowed_method_counts
            != tuple(sorted(self.allowed_method_counts, key=lambda item: item[0]))
            or len({method for method, _count in self.allowed_method_counts})
            != len(self.allowed_method_counts)
            or any(
                method not in _ALLOWED_METHODS or type(count) is not int or count < 1
                for method, count in self.allowed_method_counts
            )
            or sum(count for _method, count in self.allowed_method_counts)
            != self.permitted_rpc_call_count
            or violation_count > self.http_request_count
            or self.status != expected_status
            or self.boundary_drained is not True
        ):
            raise ValueError("read-only RPC test scope snapshot is inconsistent")
        if not self.verify():
            raise ValueError("read-only RPC test scope snapshot hash is inconsistent")

    def to_dict(self, *, include_snapshot_sha256: bool = True) -> dict[str, object]:
        """Return the endpoint-free canonical primitive projection."""

        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "attempt_binding_sha256": self.attempt_binding_sha256,
            "selection_sha256": self.selection_sha256,
            "descriptor_sha256": self.descriptor_sha256,
            "sequence_index": self.sequence_index,
            "policy_sha256": self.policy_sha256,
            "expected_chain_id": self.expected_chain_id,
            "pinned_block_number": self.pinned_block_number,
            "pinned_block_hash": self.pinned_block_hash,
            "status": self.status,
            "http_request_count": self.http_request_count,
            "permitted_rpc_call_count": self.permitted_rpc_call_count,
            "origin_attempted_rpc_call_count": self.origin_attempted_rpc_call_count,
            "origin_validated_rpc_call_count": self.origin_validated_rpc_call_count,
            "synthetic_rpc_call_count": self.synthetic_rpc_call_count,
            "denied_request_count": self.denied_request_count,
            "malformed_request_count": self.malformed_request_count,
            "limit_exceeded_request_count": self.limit_exceeded_request_count,
            "upstream_error_request_count": self.upstream_error_request_count,
            "allowed_method_counts": [
                {"method": method, "count": count} for method, count in self.allowed_method_counts
            ],
            "method_log_sha256": self.method_log_sha256,
            "boundary_drained": self.boundary_drained,
        }
        if include_snapshot_sha256:
            result["snapshot_sha256"] = self.snapshot_sha256
        return result

    def verify(self) -> bool:
        """Verify the scope snapshot's self-hash without reading external state."""

        return self.snapshot_sha256 == _canonical_sha256(
            self.to_dict(include_snapshot_sha256=False)
        )


@dataclass
class _ReadOnlyRpcTestScopeAccumulator:
    attempt_binding_sha256: str
    selection_sha256: str
    descriptor_sha256: str
    sequence_index: int
    http_request_count: int = 0
    permitted_rpc_call_count: int = 0
    origin_attempted_rpc_call_count: int = 0
    origin_validated_rpc_call_count: int = 0
    synthetic_rpc_call_count: int = 0
    denied_request_count: int = 0
    malformed_request_count: int = 0
    limit_exceeded_request_count: int = 0
    upstream_error_request_count: int = 0
    allowed_method_counts: dict[str, int] = field(default_factory=dict)
    method_log: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _AcceptBoundaryCheckpoint:
    """Internal loopback checkpoint that pauses the accept loop at one generation."""

    source_port: int
    accepted: threading.Event = field(default_factory=threading.Event)
    release: threading.Event = field(default_factory=threading.Event)


@dataclass(frozen=True)
class _AcceptedRequestMetadata:
    """Generation or internal checkpoint bound to one accepted listener socket."""

    generation: int | None
    checkpoint: _AcceptBoundaryCheckpoint | None


@dataclass(frozen=True)
class _OriginObservation:
    chain_id: int
    block_number: int
    block_hash: str

    def __post_init__(self) -> None:
        if (
            type(self.chain_id) is not int
            or not 1 <= self.chain_id < 2**64
            or type(self.block_number) is not int
            or not 0 <= self.block_number < 2**64
            or _BLOCK_HASH_PATTERN.fullmatch(self.block_hash) is None
        ):
            raise ValueError("origin observation is invalid")

    @property
    def observation_sha256(self) -> str:
        return _canonical_sha256(
            {
                "schema_version": "1.0",
                "chain_id": self.chain_id,
                "block_number": self.block_number,
                "block_hash": self.block_hash,
            }
        )


@dataclass(frozen=True)
class _PreparedCall:
    request_id: int | str
    method: str
    origin_method: str
    payload: dict[str, object]
    synthetic_result: object | None
    is_synthetic: bool


class _RejectionKind(StrEnum):
    DENIED = "denied"
    LIMIT = "limit"
    MALFORMED = "malformed"
    UPSTREAM = "upstream"


class _BridgeRejection(Exception):
    def __init__(self, kind: _RejectionKind) -> None:
        super().__init__("read-only RPC request rejected")
        self.kind = kind


class _DuplicateKeyError(ValueError):
    pass


class _BridgeHttpServer(ThreadingHTTPServer):
    # Handler threads cannot be allowed to make interpreter shutdown unbounded.
    # Clean bridge shutdown still requires the explicitly tracked set to drain.
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = False

    bridge: ReadOnlyRpcBridge

    def __init__(self, bridge: ReadOnlyRpcBridge, *, max_concurrent_handlers: int) -> None:
        self.request_queue_size = min(max_concurrent_handlers, 64)
        self._handler_slots = threading.BoundedSemaphore(max_concurrent_handlers)
        self._active_connections_lock = threading.Lock()
        self._active_connections: set[socket.socket] = set()
        self._handlers_drained = threading.Event()
        self._handlers_drained.set()
        self._admission_lock = threading.Lock()
        self._admission_thread: threading.Thread | None = None
        self._accepted_metadata_lock = threading.Lock()
        self._accepted_metadata: dict[socket.socket, _AcceptedRequestMetadata] = {}
        self._checkpoint_lock = threading.Lock()
        self._checkpoints_by_source_port: dict[int, _AcceptBoundaryCheckpoint] = {}
        super().__init__(("127.0.0.1", 0), _BridgeRequestHandler)
        self.bridge = bridge

    def get_request(self) -> tuple[socket.socket, object]:
        accept_generation = self.bridge._current_accept_generation()
        request, client_address = super().get_request()
        request.settimeout(self.bridge._timeout_seconds)
        checkpoint: _AcceptBoundaryCheckpoint | None = None
        if (
            isinstance(client_address, tuple)
            and len(client_address) >= 2
            and isinstance(client_address[1], int)
        ):
            with self._checkpoint_lock:
                checkpoint = self._checkpoints_by_source_port.pop(client_address[1], None)
        if checkpoint is None:
            self.bridge._register_accepted_http_request(accept_generation)
            metadata = _AcceptedRequestMetadata(
                generation=accept_generation,
                checkpoint=None,
            )
        else:
            metadata = _AcceptedRequestMetadata(generation=None, checkpoint=checkpoint)
        with self._accepted_metadata_lock:
            self._accepted_metadata[request] = metadata
        return request, client_address

    def process_request(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: object,
    ) -> None:
        if not isinstance(request, socket.socket):
            raise ReadOnlyRpcBridgeError("read-only RPC bridge accepted a non-stream socket")
        with self._accepted_metadata_lock:
            metadata = self._accepted_metadata.pop(request, None)
        if metadata is None:
            _close_connection(request)
            raise ReadOnlyRpcBridgeError("read-only RPC accepted-request metadata is missing")
        if metadata.checkpoint is not None:
            _close_connection(request)
            metadata.checkpoint.accepted.set()
            metadata.checkpoint.release.wait(self.bridge._shutdown_timeout_seconds)
            return
        if metadata.generation is None:
            _close_connection(request)
            raise ReadOnlyRpcBridgeError("read-only RPC accept generation is missing")
        admitted, saturated = self.bridge._admit_http_request(metadata.generation)
        if saturated:
            self.stop_admission()
        if not admitted:
            _close_connection(request)
            return
        if not self._handler_slots.acquire(blocking=False):
            try:
                self.bridge._record_rejection(_RejectionKind.LIMIT)
                _reject_capacity_connection(request)
            finally:
                self.bridge._finish_admitted_http_request()
            return
        with self._active_connections_lock:
            self._active_connections.add(request)
            self._handlers_drained.clear()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._finish_handler(request)
            raise

    def accept_boundary_checkpoint(self, timeout_seconds: float) -> _AcceptBoundaryCheckpoint:
        """Pause the accept loop after every connection queued before this checkpoint."""

        if timeout_seconds <= 0:
            raise ReadOnlyRpcBridgeError(
                "read-only RPC selected test scope accept checkpoint exceeded its bound"
            )
        deadline = time.monotonic() + timeout_seconds
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(max(0.001, deadline - time.monotonic()))
        checkpoint: _AcceptBoundaryCheckpoint | None = None
        checkpoint_delivered = False
        try:
            probe.bind(("127.0.0.1", 0))
            source_port = probe.getsockname()[1]
            if not isinstance(source_port, int) or not 1 <= source_port <= 65_535:
                raise ReadOnlyRpcBridgeError(
                    "read-only RPC selected test scope accept checkpoint is invalid"
                )
            checkpoint = _AcceptBoundaryCheckpoint(source_port=source_port)
            with self._checkpoint_lock:
                if source_port in self._checkpoints_by_source_port:
                    raise ReadOnlyRpcBridgeError(
                        "read-only RPC selected test scope accept checkpoint collided"
                    )
                self._checkpoints_by_source_port[source_port] = checkpoint
            host, port = cast(tuple[str, int], self.server_address)
            if host != "127.0.0.1" or not isinstance(port, int):
                raise ReadOnlyRpcBridgeError(
                    "read-only RPC selected test scope listener identity is invalid"
                )
            probe.connect((host, port))
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not checkpoint.accepted.wait(remaining):
                raise ReadOnlyRpcBridgeError(
                    "read-only RPC selected test scope accept checkpoint exceeded its bound"
                )
            checkpoint_delivered = True
            return checkpoint
        except (OSError, TimeoutError) as exc:
            raise ReadOnlyRpcBridgeError(
                "read-only RPC selected test scope accept checkpoint failed"
            ) from exc
        finally:
            probe.close()
            if checkpoint is not None and not checkpoint_delivered:
                with self._checkpoint_lock:
                    self._checkpoints_by_source_port.pop(checkpoint.source_port, None)
                checkpoint.release.set()

    def process_request_thread(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: object,
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            if isinstance(request, socket.socket):
                self._finish_handler(request)

    def close_active_connections(self) -> None:
        """Interrupt every accepted handler socket without waiting for a handler."""

        with self._active_connections_lock:
            active_connections = tuple(self._active_connections)
        for request in active_connections:
            with suppress(OSError):
                request.shutdown(socket.SHUT_RDWR)
            with suppress(OSError):
                request.close()

    def stop_admission(self) -> None:
        """Request serve-loop shutdown once without blocking its caller."""

        def stop_and_close_listener() -> None:
            self.shutdown()
            self.server_close()

        with self._admission_lock:
            if self._admission_thread is not None:
                return
            thread = threading.Thread(
                target=stop_and_close_listener,
                name="mmaudit-read-only-rpc-admission",
                daemon=True,
            )
            self._admission_thread = thread
            thread.start()

    def wait_for_admission_stop(self, timeout_seconds: float) -> bool:
        with self._admission_lock:
            thread = self._admission_thread
        if thread is None:
            return False
        thread.join(timeout=max(0.0, timeout_seconds))
        return not thread.is_alive()

    def wait_for_handlers(self, timeout_seconds: float) -> bool:
        """Return whether all tracked handlers drained inside the supplied bound."""

        if timeout_seconds <= 0 or not self._handlers_drained.wait(timeout_seconds):
            return False
        with self._active_connections_lock:
            return not self._active_connections

    def handlers_drained(self) -> bool:
        """Return a non-blocking view of the tracked handler boundary."""

        with self._active_connections_lock:
            return self._handlers_drained.is_set() and not self._active_connections

    def _finish_handler(self, request: socket.socket) -> None:
        with self._active_connections_lock:
            self._active_connections.discard(request)
            if not self._active_connections:
                self._handlers_drained.set()
        self._handler_slots.release()
        self.bridge._finish_admitted_http_request()


class _BridgeRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mmaudit-read-only-rpc"
    sys_version = ""

    def handle(self) -> None:
        bridge = cast(_BridgeHttpServer, self.server).bridge
        self._request_classified = False
        with suppress(OSError):
            super().handle()
        if not self._request_classified:
            bridge._record_rejection(_RejectionKind.MALFORMED)

    def do_POST(self) -> None:
        self._request_classified = True
        bridge = cast(_BridgeHttpServer, self.server).bridge
        bridge._handle_http_request(self)

    def do_GET(self) -> None:
        self._reject_non_post()

    def do_PUT(self) -> None:
        self._reject_non_post()

    def do_PATCH(self) -> None:
        self._reject_non_post()

    def do_DELETE(self) -> None:
        self._reject_non_post()

    def do_OPTIONS(self) -> None:
        self._reject_non_post()

    def _reject_non_post(self) -> None:
        self._request_classified = True
        bridge = cast(_BridgeHttpServer, self.server).bridge
        bridge._record_rejection(_RejectionKind.MALFORMED)
        bridge._write_rejection(self, _RejectionKind.MALFORMED)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class ReadOnlyRpcBridge:
    """Serve a bounded method-allowlisting proxy on an ephemeral loopback port."""

    def __init__(
        self,
        origin_endpoint: str,
        *,
        expected_chain_id: int,
        pinned_block_number: int,
        pinned_block_hash: str,
        timeout_seconds: float = 5.0,
        max_request_body_bytes: int = _DEFAULT_MAX_REQUEST_BODY_BYTES,
        max_response_body_bytes: int = _DEFAULT_MAX_RESPONSE_BODY_BYTES,
        max_batch_size: int = _DEFAULT_MAX_BATCH_SIZE,
        max_json_depth: int = _DEFAULT_MAX_JSON_DEPTH,
        max_json_nodes: int = _DEFAULT_MAX_JSON_NODES,
        max_http_requests: int = _DEFAULT_MAX_HTTP_REQUESTS,
        max_rpc_calls: int = _DEFAULT_MAX_RPC_CALLS,
        max_concurrent_handlers: int = _DEFAULT_MAX_CONCURRENT_HANDLERS,
        shutdown_timeout_seconds: float = _DEFAULT_SHUTDOWN_TIMEOUT_SECONDS,
    ) -> None:
        try:
            normalized_origin_endpoint = _numeric_loopback_endpoint(origin_endpoint)
        except ForkRpcBindingError as exc:
            raise ReadOnlyRpcBridgeError(
                "read-only RPC origin must be a credential-free loopback HTTP endpoint"
            ) from exc
        if (
            type(expected_chain_id) is not int
            or expected_chain_id < 1
            or expected_chain_id >= 2**64
            or type(pinned_block_number) is not int
            or pinned_block_number < 0
            or pinned_block_number >= 2**64
            or _BLOCK_HASH_PATTERN.fullmatch(pinned_block_hash) is None
        ):
            raise ReadOnlyRpcBridgeError("read-only RPC state identity is invalid")
        _require_bound(
            "request body", max_request_body_bytes, minimum=64, maximum=_MAX_REQUEST_BODY_BYTES
        )
        _require_bound(
            "response body",
            max_response_body_bytes,
            minimum=64,
            maximum=_MAX_RESPONSE_BODY_BYTES,
        )
        _require_bound("batch size", max_batch_size, minimum=1, maximum=_MAX_BATCH_SIZE)
        _require_bound("JSON depth", max_json_depth, minimum=4, maximum=_MAX_JSON_DEPTH)
        _require_bound("JSON nodes", max_json_nodes, minimum=16, maximum=_MAX_JSON_NODES)
        _require_bound(
            "HTTP request count",
            max_http_requests,
            minimum=1,
            maximum=_MAX_HTTP_REQUESTS,
        )
        _require_bound("RPC call count", max_rpc_calls, minimum=1, maximum=_MAX_RPC_CALLS)
        _require_bound(
            "concurrent handler count",
            max_concurrent_handlers,
            minimum=1,
            maximum=_MAX_CONCURRENT_HANDLERS,
        )
        if not 0 < timeout_seconds <= _MAX_TIMEOUT_SECONDS:
            raise ReadOnlyRpcBridgeError("read-only RPC timeout is outside the supported range")
        if not 0.05 <= shutdown_timeout_seconds <= _MAX_SHUTDOWN_TIMEOUT_SECONDS:
            raise ReadOnlyRpcBridgeError(
                "read-only RPC shutdown timeout is outside the supported range"
            )

        self._origin_endpoint = normalized_origin_endpoint
        parsed_origin = urlparse(normalized_origin_endpoint)
        if parsed_origin.hostname is None or parsed_origin.port is None:
            raise ReadOnlyRpcBridgeError("read-only RPC origin identity is invalid")
        self._origin_host = parsed_origin.hostname
        self._origin_port = parsed_origin.port
        self._expected_chain_id = expected_chain_id
        self._pinned_block_number = pinned_block_number
        self._pinned_block_hash = pinned_block_hash
        self._pinned_block_tag = hex(pinned_block_number)
        self._timeout_seconds = timeout_seconds
        self._max_request_body_bytes = max_request_body_bytes
        self._max_response_body_bytes = max_response_body_bytes
        self._max_batch_size = max_batch_size
        self._max_json_depth = max_json_depth
        self._max_json_nodes = max_json_nodes
        self._max_http_requests = max_http_requests
        self._max_rpc_calls = max_rpc_calls
        self._max_concurrent_handlers = max_concurrent_handlers
        self._shutdown_timeout_seconds = shutdown_timeout_seconds
        self._policy_sha256 = _canonical_sha256(
            {
                "version": _POLICY_VERSION,
                "allowed_methods": sorted(_ALLOWED_METHODS),
                "synthetic_methods": sorted(_SYNTHETIC_METHODS),
                "eip_1898_methods": sorted(_EIP_1898_PARAM_INDEX),
                "number_to_hash_methods": dict(sorted(_NUMBER_TO_HASH_METHOD.items())),
                "max_identity_response_body_bytes": _MAX_IDENTITY_RESPONSE_BODY_BYTES,
                "max_request_body_bytes": max_request_body_bytes,
                "max_response_body_bytes": max_response_body_bytes,
                "max_batch_size": max_batch_size,
                "max_json_depth": max_json_depth,
                "max_json_nodes": max_json_nodes,
                "max_http_requests": max_http_requests,
                "max_rpc_calls": max_rpc_calls,
                "max_concurrent_handlers": max_concurrent_handlers,
                "timeout_milliseconds": round(timeout_seconds * 1_000),
                "shutdown_timeout_milliseconds": round(shutdown_timeout_seconds * 1_000),
                "pin_semantics": "canonical_block_hash_v2",
            }
        )
        self._state_lock = threading.Lock()
        self._scope_drain_condition = threading.Condition(self._state_lock)
        self._lifecycle_lock = threading.Lock()
        self._scope_transition_lock = threading.Lock()
        self._scope_boundary_lock = threading.Lock()
        self._active_upstream_lock = threading.Lock()
        self._active_upstream_connections: dict[object, socket.socket | None] = {}
        self._upstream_shutdown_requested = False
        self._accept_generation = 0
        self._admission_closed = False
        self._pending_accepted_http_request_count = 0
        self._inflight_admitted_http_request_count = 0
        self._active_test_scope: _ReadOnlyRpcTestScopeAccumulator | None = None
        self._selected_test_scope_snapshot_sha256s: list[str] = []
        self._http_request_count = 0
        self._http_admission_saturated = False
        self._permitted_rpc_call_count = 0
        self._origin_attempted_rpc_call_count = 0
        self._origin_validated_rpc_call_count = 0
        self._synthetic_rpc_call_count = 0
        self._denied_request_count = 0
        self._malformed_request_count = 0
        self._limit_exceeded_request_count = 0
        self._upstream_error_request_count = 0
        self._allowed_method_counts: dict[str, int] = {}
        self._method_log: list[str] = []
        self._server: _BridgeHttpServer | None = None
        self._serve_thread: threading.Thread | None = None
        self._preflight_observation: _OriginObservation | None = None
        self._postflight_observation: _OriginObservation | None = None
        self._start_attempted = False
        self._started = False
        self._stop_attempted = False
        self._stopped_cleanly = False

    def __enter__(self) -> ReadOnlyRpcBridge:
        self.start()
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: object | None,
    ) -> None:
        self.stop()

    @property
    def endpoint(self) -> str:
        """Return the ephemeral bridge URL only while it is running."""

        with self._lifecycle_lock:
            if (
                self._server is None
                or not self._started
                or self._stop_attempted
                or self._stopped_cleanly
            ):
                raise ReadOnlyRpcBridgeError("read-only RPC bridge is not running")
            host = self._server.server_address[0]
            port = self._server.server_address[1]
            if host != "127.0.0.1" or not isinstance(port, int):
                raise ReadOnlyRpcBridgeError("read-only RPC bridge listener identity is invalid")
            return f"http://127.0.0.1:{port}"

    def begin_selected_test_scope(
        self,
        *,
        attempt_binding_sha256: str,
        selection_sha256: str,
        descriptor_sha256: str,
        sequence_index: int,
    ) -> None:
        """Begin exact accounting for one selected descriptor at a drained boundary."""

        _validate_test_scope_identity(
            attempt_binding_sha256=attempt_binding_sha256,
            selection_sha256=selection_sha256,
            descriptor_sha256=descriptor_sha256,
            sequence_index=sequence_index,
        )
        deadline = time.monotonic() + self._shutdown_timeout_seconds
        if not self._scope_transition_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
            raise ReadOnlyRpcBridgeError(
                "read-only RPC selected test scope boundary exceeded its bound"
            )
        checkpoint: _AcceptBoundaryCheckpoint | None = None
        try:
            server = self._running_server_for_test_scope()
            with self._scope_boundary_lock, self._state_lock:
                if self._active_test_scope is not None:
                    raise ReadOnlyRpcBridgeError(
                        "read-only RPC selected test scopes cannot overlap"
                    )
            checkpoint = server.accept_boundary_checkpoint(max(0.0, deadline - time.monotonic()))
            if not self._wait_for_test_scope_boundary_drained(server, deadline=deadline):
                raise ReadOnlyRpcBridgeError(
                    "read-only RPC selected test scope boundary exceeded its bound"
                )
            with self._scope_boundary_lock:
                if not self._test_scope_boundary_drained(server):
                    raise ReadOnlyRpcBridgeError(
                        "read-only RPC selected test scope requires a drained boundary"
                    )
                with self._state_lock:
                    if self._active_test_scope is not None:
                        raise ReadOnlyRpcBridgeError(
                            "read-only RPC selected test scopes cannot overlap"
                        )
                    self._accept_generation += 1
                    self._active_test_scope = _ReadOnlyRpcTestScopeAccumulator(
                        attempt_binding_sha256=attempt_binding_sha256,
                        selection_sha256=selection_sha256,
                        descriptor_sha256=descriptor_sha256,
                        sequence_index=sequence_index,
                    )
        finally:
            if checkpoint is not None:
                checkpoint.release.set()
            self._scope_transition_lock.release()

    def end_selected_test_scope(
        self,
        *,
        attempt_binding_sha256: str,
        selection_sha256: str,
        descriptor_sha256: str,
        sequence_index: int,
    ) -> ReadOnlyRpcTestScopeSnapshot:
        """Seal exact accounting for one selected descriptor at a drained boundary."""

        identity = _validate_test_scope_identity(
            attempt_binding_sha256=attempt_binding_sha256,
            selection_sha256=selection_sha256,
            descriptor_sha256=descriptor_sha256,
            sequence_index=sequence_index,
        )
        deadline = time.monotonic() + self._shutdown_timeout_seconds
        if not self._scope_transition_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
            raise ReadOnlyRpcBridgeError(
                "read-only RPC selected test scope boundary exceeded its bound"
            )
        checkpoint: _AcceptBoundaryCheckpoint | None = None
        try:
            server = self._running_server_for_test_scope()
            with self._scope_boundary_lock, self._state_lock:
                active_scope = self._active_test_scope
                if active_scope is None:
                    raise ReadOnlyRpcBridgeError("read-only RPC selected test scope is not active")
                active_identity = (
                    active_scope.attempt_binding_sha256,
                    active_scope.selection_sha256,
                    active_scope.descriptor_sha256,
                    active_scope.sequence_index,
                )
                if active_identity != identity:
                    raise ReadOnlyRpcBridgeError(
                        "read-only RPC selected test scope identity does not match"
                    )
            checkpoint = server.accept_boundary_checkpoint(max(0.0, deadline - time.monotonic()))
            if not self._wait_for_test_scope_boundary_drained(server, deadline=deadline):
                raise ReadOnlyRpcBridgeError(
                    "read-only RPC selected test scope boundary exceeded its bound"
                )
            with self._scope_boundary_lock:
                if not self._test_scope_boundary_drained(server):
                    raise ReadOnlyRpcBridgeError(
                        "read-only RPC selected test scope requires a drained boundary"
                    )
                with self._state_lock:
                    active_scope = self._active_test_scope
                    if active_scope is None:
                        raise ReadOnlyRpcBridgeError(
                            "read-only RPC selected test scope is not active"
                        )
                    active_identity = (
                        active_scope.attempt_binding_sha256,
                        active_scope.selection_sha256,
                        active_scope.descriptor_sha256,
                        active_scope.sequence_index,
                    )
                    if active_identity != identity:
                        raise ReadOnlyRpcBridgeError(
                            "read-only RPC selected test scope identity does not match"
                        )
                    snapshot = self._seal_test_scope_snapshot(active_scope)
                    if snapshot.snapshot_sha256 in self._selected_test_scope_snapshot_sha256s:
                        raise ReadOnlyRpcBridgeError(
                            "read-only RPC selected test scope snapshot is duplicated"
                        )
                    self._selected_test_scope_snapshot_sha256s.append(snapshot.snapshot_sha256)
                    self._active_test_scope = None
                    self._accept_generation += 1
                    return snapshot
        finally:
            if checkpoint is not None:
                checkpoint.release.set()
            self._scope_transition_lock.release()

    def start(self) -> None:
        """Attest the exact origin state, then bind and start the loopback listener."""

        with self._lifecycle_lock:
            if self._start_attempted:
                raise ReadOnlyRpcBridgeError("read-only RPC bridge cannot be started twice")
            self._start_attempted = True

        try:
            preflight_observation = self._observe_origin_identity(
                timeout_seconds=self._timeout_seconds
            )
        except (
            ReadOnlyRpcBridgeError,
            _BridgeRejection,
            HTTPException,
            OSError,
            TimeoutError,
            ValueError,
        ) as exc:
            raise ReadOnlyRpcBridgeError("read-only RPC origin identity preflight failed") from exc

        with self._lifecycle_lock:
            server: _BridgeHttpServer | None = None
            try:
                server = _BridgeHttpServer(
                    self,
                    max_concurrent_handlers=self._max_concurrent_handlers,
                )
                thread = threading.Thread(
                    target=server.serve_forever,
                    kwargs={"poll_interval": 0.05},
                    name="mmaudit-read-only-rpc",
                    daemon=True,
                )
                thread.start()
            except (OSError, RuntimeError) as exc:
                if server is not None:
                    server.server_close()
                raise ReadOnlyRpcBridgeError(
                    "read-only RPC bridge could not bind its loopback listener"
                ) from exc
            self._preflight_observation = preflight_observation
            self._server = server
            self._serve_thread = thread
            self._started = True

    def stop(self) -> None:
        """Stop resources within one deadline, then re-attest the origin state."""

        with self._scope_transition_lock, self._scope_boundary_lock, self._lifecycle_lock:
            if not self._started:
                raise ReadOnlyRpcBridgeError("read-only RPC bridge was not started")
            if self._stopped_cleanly:
                return
            if self._stop_attempted:
                raise ReadOnlyRpcBridgeError("read-only RPC bridge shutdown was already attempted")
            server = self._server
            thread = self._serve_thread
            preflight_observation = self._preflight_observation
            if server is None or thread is None or preflight_observation is None:
                raise ReadOnlyRpcBridgeError("read-only RPC bridge lifecycle is inconsistent")
            with self._state_lock:
                abandoned_test_scope = self._active_test_scope is not None
                self._active_test_scope = None
                self._admission_closed = True
                self._accept_generation += 1
            self._stop_attempted = True

        deadline = time.monotonic() + self._shutdown_timeout_seconds
        cleanup_errors: list[BaseException] = []

        def close_bridge_resources() -> None:
            server.stop_admission()
            server.close_active_connections()
            self._close_active_upstream_responses()
            if not server.wait_for_admission_stop(max(0.0, deadline - time.monotonic())):
                cleanup_errors.append(
                    ReadOnlyRpcBridgeError("read-only RPC bridge admission thread did not stop")
                )
            try:
                # block_on_close=False prevents ThreadingMixIn from joining handlers here.
                server.server_close()
            except (OSError, RuntimeError) as exc:
                cleanup_errors.append(exc)

        cleanup_thread = threading.Thread(
            target=close_bridge_resources,
            name="mmaudit-read-only-rpc-cleanup",
            daemon=True,
        )
        cleanup_thread.start()
        cleanup_thread.join(timeout=max(0.0, deadline - time.monotonic()))
        cleanup_finished = not cleanup_thread.is_alive()
        handlers_drained = (
            server.wait_for_handlers(max(0.0, deadline - time.monotonic()))
            if cleanup_finished
            else False
        )
        upstreams_drained = handlers_drained and self._upstream_resources_drained()
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if (
            not cleanup_finished
            or cleanup_errors
            or not handlers_drained
            or not upstreams_drained
            or thread.is_alive()
            or time.monotonic() > deadline
        ):
            cause = cleanup_errors[0] if cleanup_errors else None
            if cause is None:
                raise ReadOnlyRpcBridgeError(
                    "read-only RPC bridge did not stop cleanly within its absolute bound"
                )
            raise ReadOnlyRpcBridgeError(
                "read-only RPC bridge did not stop cleanly within its absolute bound"
            ) from cause

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ReadOnlyRpcBridgeError(
                "read-only RPC origin identity postflight exceeded the shutdown bound"
            )
        try:
            postflight_observation = self._observe_origin_identity(
                timeout_seconds=min(self._timeout_seconds, remaining)
            )
        except (
            ReadOnlyRpcBridgeError,
            _BridgeRejection,
            HTTPException,
            OSError,
            TimeoutError,
            ValueError,
        ) as exc:
            raise ReadOnlyRpcBridgeError("read-only RPC origin identity postflight failed") from exc
        if postflight_observation != preflight_observation or time.monotonic() > deadline:
            raise ReadOnlyRpcBridgeError("read-only RPC origin identity postflight failed")
        if abandoned_test_scope:
            raise ReadOnlyRpcBridgeError(
                "read-only RPC selected test scope was abandoned during bridge shutdown"
            )
        with self._lifecycle_lock:
            self._postflight_observation = postflight_observation
            self._stopped_cleanly = True

    def snapshot(self) -> ReadOnlyRpcBridgeSnapshot:
        """Seal the endpoint-free final snapshot after a clean stop."""

        with self._lifecycle_lock:
            if not self._started or not self._stopped_cleanly:
                raise ReadOnlyRpcBridgeError(
                    "read-only RPC bridge snapshot requires a clean stopped bridge"
                )
            preflight_observation = self._preflight_observation
            postflight_observation = self._postflight_observation
            if (
                preflight_observation is None
                or postflight_observation is None
                or preflight_observation != postflight_observation
            ):
                raise ReadOnlyRpcBridgeError(
                    "read-only RPC bridge origin observations are inconsistent"
                )
        with self._state_lock:
            allowed_method_counts = tuple(sorted(self._allowed_method_counts.items()))
            method_log_sha256 = _canonical_sha256(self._method_log)
            selected_test_scope_snapshot_sha256s = tuple(self._selected_test_scope_snapshot_sha256s)
            violation_count = (
                self._denied_request_count
                + self._malformed_request_count
                + self._limit_exceeded_request_count
                + self._upstream_error_request_count
            )
            payload: dict[str, object] = {
                "schema_version": "2.0",
                "status": "violation" if violation_count else "enforced",
                "policy_sha256": self._policy_sha256,
                "expected_chain_id": self._expected_chain_id,
                "pinned_block_number": self._pinned_block_number,
                "pinned_block_hash": self._pinned_block_hash,
                "preflight_origin_observation_sha256": (preflight_observation.observation_sha256),
                "postflight_origin_observation_sha256": (postflight_observation.observation_sha256),
                "origin_state_stable": True,
                "http_request_count": self._http_request_count,
                "permitted_rpc_call_count": self._permitted_rpc_call_count,
                "origin_attempted_rpc_call_count": self._origin_attempted_rpc_call_count,
                "origin_validated_rpc_call_count": self._origin_validated_rpc_call_count,
                "synthetic_rpc_call_count": self._synthetic_rpc_call_count,
                "denied_request_count": self._denied_request_count,
                "malformed_request_count": self._malformed_request_count,
                "limit_exceeded_request_count": self._limit_exceeded_request_count,
                "upstream_error_request_count": self._upstream_error_request_count,
                "allowed_method_counts": [
                    {"method": method, "count": count} for method, count in allowed_method_counts
                ],
                "method_log_sha256": method_log_sha256,
                "stopped_cleanly": True,
            }
            if selected_test_scope_snapshot_sha256s:
                payload["selected_test_scope_snapshot_sha256s"] = list(
                    selected_test_scope_snapshot_sha256s
                )
            snapshot_sha256 = _canonical_sha256(payload)
            return ReadOnlyRpcBridgeSnapshot(
                schema_version="2.0",
                status="violation" if violation_count else "enforced",
                policy_sha256=self._policy_sha256,
                expected_chain_id=self._expected_chain_id,
                pinned_block_number=self._pinned_block_number,
                pinned_block_hash=self._pinned_block_hash,
                preflight_origin_observation_sha256=(preflight_observation.observation_sha256),
                postflight_origin_observation_sha256=(postflight_observation.observation_sha256),
                origin_state_stable=True,
                http_request_count=self._http_request_count,
                permitted_rpc_call_count=self._permitted_rpc_call_count,
                origin_attempted_rpc_call_count=self._origin_attempted_rpc_call_count,
                origin_validated_rpc_call_count=self._origin_validated_rpc_call_count,
                synthetic_rpc_call_count=self._synthetic_rpc_call_count,
                denied_request_count=self._denied_request_count,
                malformed_request_count=self._malformed_request_count,
                limit_exceeded_request_count=self._limit_exceeded_request_count,
                upstream_error_request_count=self._upstream_error_request_count,
                allowed_method_counts=allowed_method_counts,
                method_log_sha256=method_log_sha256,
                stopped_cleanly=True,
                snapshot_sha256=snapshot_sha256,
                selected_test_scope_snapshot_sha256s=(selected_test_scope_snapshot_sha256s),
            )

    def _running_server_for_test_scope(self) -> _BridgeHttpServer:
        with self._lifecycle_lock:
            if (
                self._server is None
                or not self._started
                or self._stop_attempted
                or self._stopped_cleanly
            ):
                raise ReadOnlyRpcBridgeError("read-only RPC bridge is not running")
            return self._server

    def _test_scope_boundary_drained(self, server: _BridgeHttpServer) -> bool:
        with self._state_lock:
            admitted_requests_drained = (
                self._pending_accepted_http_request_count == 0
                and self._inflight_admitted_http_request_count == 0
            )
        return (
            admitted_requests_drained
            and server.handlers_drained()
            and self._upstream_resources_drained()
        )

    def _wait_for_test_scope_boundary_drained(
        self,
        server: _BridgeHttpServer,
        *,
        deadline: float,
    ) -> bool:
        """Wait for accepted and admitted pre-boundary work within one absolute bound."""

        with self._scope_drain_condition:
            while self._pending_accepted_http_request_count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._scope_drain_condition.wait(remaining)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not server.wait_for_handlers(remaining):
            return False
        with self._scope_drain_condition:
            while self._inflight_admitted_http_request_count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._scope_drain_condition.wait(remaining)
        return time.monotonic() <= deadline and self._upstream_resources_drained()

    def _current_accept_generation(self) -> int:
        """Capture the generation before the listener blocks in accept()."""

        with self._scope_boundary_lock:
            return self._accept_generation

    def _register_accepted_http_request(self, generation: int) -> None:
        """Track a listener socket before it can cross into request admission."""

        with self._scope_boundary_lock, self._scope_drain_condition:
            if type(generation) is not int or generation < 0:
                raise ReadOnlyRpcBridgeError("read-only RPC accept generation is invalid")
            self._pending_accepted_http_request_count += 1
            self._scope_drain_condition.notify_all()

    def _seal_test_scope_snapshot(
        self,
        scope: _ReadOnlyRpcTestScopeAccumulator,
    ) -> ReadOnlyRpcTestScopeSnapshot:
        violation_count = (
            scope.denied_request_count
            + scope.malformed_request_count
            + scope.limit_exceeded_request_count
            + scope.upstream_error_request_count
        )
        status: Literal["validated", "not_observed", "violation"]
        if violation_count or (
            scope.origin_validated_rpc_call_count != scope.origin_attempted_rpc_call_count
        ):
            status = "violation"
        elif scope.origin_attempted_rpc_call_count:
            status = "validated"
        else:
            status = "not_observed"
        allowed_method_counts = tuple(sorted(scope.allowed_method_counts.items()))
        method_log_sha256 = _canonical_sha256(scope.method_log)
        payload: dict[str, object] = {
            "schema_version": "1.0",
            "attempt_binding_sha256": scope.attempt_binding_sha256,
            "selection_sha256": scope.selection_sha256,
            "descriptor_sha256": scope.descriptor_sha256,
            "sequence_index": scope.sequence_index,
            "policy_sha256": self._policy_sha256,
            "expected_chain_id": self._expected_chain_id,
            "pinned_block_number": self._pinned_block_number,
            "pinned_block_hash": self._pinned_block_hash,
            "status": status,
            "http_request_count": scope.http_request_count,
            "permitted_rpc_call_count": scope.permitted_rpc_call_count,
            "origin_attempted_rpc_call_count": scope.origin_attempted_rpc_call_count,
            "origin_validated_rpc_call_count": scope.origin_validated_rpc_call_count,
            "synthetic_rpc_call_count": scope.synthetic_rpc_call_count,
            "denied_request_count": scope.denied_request_count,
            "malformed_request_count": scope.malformed_request_count,
            "limit_exceeded_request_count": scope.limit_exceeded_request_count,
            "upstream_error_request_count": scope.upstream_error_request_count,
            "allowed_method_counts": [
                {"method": method, "count": count} for method, count in allowed_method_counts
            ],
            "method_log_sha256": method_log_sha256,
            "boundary_drained": True,
        }
        snapshot_sha256 = _canonical_sha256(payload)
        return ReadOnlyRpcTestScopeSnapshot(
            schema_version="1.0",
            attempt_binding_sha256=scope.attempt_binding_sha256,
            selection_sha256=scope.selection_sha256,
            descriptor_sha256=scope.descriptor_sha256,
            sequence_index=scope.sequence_index,
            policy_sha256=self._policy_sha256,
            expected_chain_id=self._expected_chain_id,
            pinned_block_number=self._pinned_block_number,
            pinned_block_hash=self._pinned_block_hash,
            status=status,
            http_request_count=scope.http_request_count,
            permitted_rpc_call_count=scope.permitted_rpc_call_count,
            origin_attempted_rpc_call_count=scope.origin_attempted_rpc_call_count,
            origin_validated_rpc_call_count=scope.origin_validated_rpc_call_count,
            synthetic_rpc_call_count=scope.synthetic_rpc_call_count,
            denied_request_count=scope.denied_request_count,
            malformed_request_count=scope.malformed_request_count,
            limit_exceeded_request_count=scope.limit_exceeded_request_count,
            upstream_error_request_count=scope.upstream_error_request_count,
            allowed_method_counts=allowed_method_counts,
            method_log_sha256=method_log_sha256,
            boundary_drained=True,
            snapshot_sha256=snapshot_sha256,
        )

    def _observe_origin_identity(self, *, timeout_seconds: float) -> _OriginObservation:
        request_ids = (
            "mmaudit-origin-identity-chain",
            "mmaudit-origin-identity-block-hash",
            "mmaudit-origin-identity-block-number",
        )
        requests: list[dict[str, object]] = [
            {
                "jsonrpc": "2.0",
                "id": request_ids[0],
                "method": "eth_chainId",
                "params": [],
            },
            {
                "jsonrpc": "2.0",
                "id": request_ids[1],
                "method": "eth_getBlockByHash",
                "params": [self._pinned_block_hash, False],
            },
            {
                "jsonrpc": "2.0",
                "id": request_ids[2],
                "method": "eth_getBlockByNumber",
                "params": [self._pinned_block_tag, False],
            },
        ]
        body = _encode_json(requests)
        connection = HTTPConnection(
            self._origin_host,
            self._origin_port,
            timeout=timeout_seconds,
        )
        deadline = time.monotonic() + timeout_seconds
        deadline_expired = threading.Event()

        def expire_identity_connection() -> None:
            deadline_expired.set()
            transport_socket = connection.sock
            if transport_socket is not None:
                _close_connection(transport_socket)

        deadline_timer = threading.Timer(
            timeout_seconds,
            expire_identity_connection,
        )
        deadline_timer.name = "mmaudit-read-only-rpc-identity-deadline"
        deadline_timer.daemon = True
        deadline_timer.start()
        response_body = bytearray()
        try:
            connection.connect()
            connection.request(
                "POST",
                "/",
                body=body,
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            if response.status != 200:
                raise ReadOnlyRpcBridgeError("origin identity request failed")
            content_lengths = [
                value for name, value in response.getheaders() if name.lower() == "content-length"
            ]
            if len(content_lengths) > 1 or (
                content_lengths
                and (
                    not content_lengths[0].isdigit()
                    or int(content_lengths[0]) > _MAX_IDENTITY_RESPONSE_BODY_BYTES
                )
            ):
                raise ReadOnlyRpcBridgeError("origin identity response is invalid")
            while True:
                if deadline_expired.is_set() or time.monotonic() > deadline:
                    raise ReadOnlyRpcBridgeError("origin identity request timed out")
                chunk = response.read(65_536)
                if not chunk:
                    break
                response_body.extend(chunk)
                if len(response_body) > _MAX_IDENTITY_RESPONSE_BODY_BYTES:
                    raise ReadOnlyRpcBridgeError("origin identity response is invalid")
        finally:
            deadline_timer.cancel()
            with suppress(OSError):
                connection.close()
            deadline_timer.join(timeout=0.1)
        if deadline_expired.is_set() or time.monotonic() > deadline:
            raise ReadOnlyRpcBridgeError("origin identity request timed out")
        payload = _strict_json(
            bytes(response_body),
            max_depth=self._max_json_depth,
            max_nodes=self._max_json_nodes,
            failure_kind=_RejectionKind.UPSTREAM,
        )
        if not isinstance(payload, list) or len(payload) != len(request_ids):
            raise ReadOnlyRpcBridgeError("origin identity response is invalid")
        by_id: dict[str, object] = {}
        for item in payload:
            if (
                not isinstance(item, dict)
                or item.get("jsonrpc") != "2.0"
                or set(item) != {"jsonrpc", "id", "result"}
                or item.get("id") not in request_ids
                or not isinstance(item.get("id"), str)
            ):
                raise ReadOnlyRpcBridgeError("origin identity response is invalid")
            response_id = cast(str, item["id"])
            if response_id in by_id:
                raise ReadOnlyRpcBridgeError("origin identity response is invalid")
            by_id[response_id] = item["result"]
        if set(by_id) != set(request_ids):
            raise ReadOnlyRpcBridgeError("origin identity response is invalid")
        chain_id = _rpc_quantity_to_int(by_id[request_ids[0]])
        block_by_hash = by_id[request_ids[1]]
        block_by_number = by_id[request_ids[2]]
        if not _is_exact_pinned_block(
            block_by_hash,
            self._pinned_block_tag,
            self._pinned_block_hash,
        ) or not _is_exact_pinned_block(
            block_by_number,
            self._pinned_block_tag,
            self._pinned_block_hash,
        ):
            raise ReadOnlyRpcBridgeError("origin identity response is invalid")
        observation = _OriginObservation(
            chain_id=chain_id,
            block_number=self._pinned_block_number,
            block_hash=self._pinned_block_hash,
        )
        if (
            observation.chain_id != self._expected_chain_id
            or observation.block_number != self._pinned_block_number
            or observation.block_hash != self._pinned_block_hash
        ):
            raise ReadOnlyRpcBridgeError("origin identity differs from expected state")
        return observation

    def _handle_http_request(self, handler: _BridgeRequestHandler) -> None:
        try:
            body = self._read_request_body(handler)
            payload = _strict_json(
                body,
                max_depth=self._max_json_depth,
                max_nodes=self._max_json_nodes,
                failure_kind=_RejectionKind.MALFORMED,
            )
            prepared, is_batch = self._prepare_payload(payload)
            outbound_calls = [call for call in prepared if not call.is_synthetic]
            outbound_body = self._serialize_outbound(outbound_calls, is_batch=is_batch)
            self._record_permitted(prepared, origin_attempted_count=len(outbound_calls))
            upstream_responses = (
                self._forward(outbound_body, outbound_calls, is_batch=is_batch)
                if outbound_calls
                else {}
            )
            response_payload = self._combine_responses(
                prepared,
                upstream_responses,
                is_batch=is_batch,
            )
            response_body = _encode_json(response_payload)
            if len(response_body) > self._max_response_body_bytes:
                raise _BridgeRejection(_RejectionKind.UPSTREAM)
            self._record_origin_validated(len(outbound_calls))
        except _BridgeRejection as exc:
            self._record_rejection(exc.kind)
            self._write_rejection(handler, exc.kind)
            return
        except Exception:
            self._record_rejection(_RejectionKind.UPSTREAM)
            self._write_rejection(handler, _RejectionKind.UPSTREAM)
            return
        self._write_response(handler, 200, response_body)

    def _read_request_body(self, handler: _BridgeRequestHandler) -> bytes:
        if handler.path != "/":
            raise _BridgeRejection(_RejectionKind.MALFORMED)
        if any(handler.headers.get_all(name) for name in _SENSITIVE_INBOUND_HEADERS):
            raise _BridgeRejection(_RejectionKind.DENIED)
        if handler.headers.get_all("Transfer-Encoding"):
            raise _BridgeRejection(_RejectionKind.MALFORMED)
        content_lengths = handler.headers.get_all("Content-Length")
        if (
            content_lengths is None
            or len(content_lengths) != 1
            or re.fullmatch(r"(?:0|[1-9][0-9]*)", content_lengths[0]) is None
        ):
            raise _BridgeRejection(_RejectionKind.MALFORMED)
        content_length = int(content_lengths[0])
        if content_length < 2 or content_length > self._max_request_body_bytes:
            raise _BridgeRejection(_RejectionKind.LIMIT)
        content_type = handler.headers.get("Content-Type", "").lower().replace(" ", "")
        if content_type not in {"application/json", "application/json;charset=utf-8"}:
            raise _BridgeRejection(_RejectionKind.MALFORMED)
        try:
            handler.connection.settimeout(self._timeout_seconds)
            body = handler.rfile.read(content_length)
        except (OSError, TimeoutError):
            raise _BridgeRejection(_RejectionKind.MALFORMED) from None
        if len(body) != content_length:
            raise _BridgeRejection(_RejectionKind.MALFORMED)
        return body

    def _prepare_payload(self, payload: object) -> tuple[list[_PreparedCall], bool]:
        if isinstance(payload, list):
            if not payload or len(payload) > self._max_batch_size:
                raise _BridgeRejection(_RejectionKind.LIMIT)
            request_items = payload
            is_batch = True
        elif isinstance(payload, dict):
            request_items = [payload]
            is_batch = False
        else:
            raise _BridgeRejection(_RejectionKind.MALFORMED)

        prepared = [self._prepare_call(item) for item in request_items]
        request_ids = [_rpc_id_key(call.request_id) for call in prepared]
        if len(request_ids) != len(set(request_ids)):
            raise _BridgeRejection(_RejectionKind.MALFORMED)
        return prepared, is_batch

    def _prepare_call(self, item: object) -> _PreparedCall:
        if not isinstance(item, dict):
            raise _BridgeRejection(_RejectionKind.MALFORMED)
        if not {"jsonrpc", "id", "method"} <= item.keys() or not set(item) <= {
            "jsonrpc",
            "id",
            "method",
            "params",
        }:
            raise _BridgeRejection(_RejectionKind.MALFORMED)
        request_id = item["id"]
        if not _valid_rpc_id(request_id):
            raise _BridgeRejection(_RejectionKind.MALFORMED)
        if item["jsonrpc"] != "2.0":
            raise _BridgeRejection(_RejectionKind.MALFORMED)
        method = item["method"]
        if not isinstance(method, str):
            raise _BridgeRejection(_RejectionKind.MALFORMED)
        if method not in _ALLOWED_METHODS:
            raise _BridgeRejection(_RejectionKind.DENIED)
        params = item.get("params", [])
        if not isinstance(params, list) or len(params) > _MAX_RPC_PARAMS:
            raise _BridgeRejection(_RejectionKind.MALFORMED)
        minimum_arity, maximum_arity = _METHOD_ARITY[method]
        if not minimum_arity <= len(params) <= maximum_arity:
            raise _BridgeRejection(_RejectionKind.MALFORMED)
        normalized_params = copy.deepcopy(params)
        self._pin_params(method, normalized_params)
        origin_method = _NUMBER_TO_HASH_METHOD.get(method, method)
        synthetic_result: object | None = None
        if method == "eth_chainId":
            synthetic_result = hex(self._expected_chain_id)
        elif method == "eth_blockNumber":
            synthetic_result = self._pinned_block_tag
        elif method == "net_version":
            synthetic_result = str(self._expected_chain_id)
        return _PreparedCall(
            request_id=cast(int | str, request_id),
            method=method,
            origin_method=origin_method,
            payload={
                "jsonrpc": "2.0",
                "id": request_id,
                "method": origin_method,
                "params": normalized_params,
            },
            synthetic_result=synthetic_result,
            is_synthetic=method in _SYNTHETIC_METHODS,
        )

    def _pin_params(self, method: str, params: list[object]) -> None:
        eip_1898_index = _EIP_1898_PARAM_INDEX.get(method)
        if eip_1898_index is not None:
            if eip_1898_index == len(params) and method == "eth_call":
                params.append(self._canonical_block_reference())
            else:
                params[eip_1898_index] = self._normalize_block_reference(params[eip_1898_index])
        if method in _NUMBER_TO_HASH_METHOD:
            self._normalize_block_tag(params[0])
            params[0] = self._pinned_block_hash
        hash_index = _HASH_PARAM_INDEX.get(method)
        if hash_index is not None:
            params[hash_index] = self._normalize_block_hash(params[hash_index])
        if method == "eth_getBlockReceipts":
            value = params[0]
            if isinstance(value, str) and _BLOCK_HASH_PATTERN.fullmatch(value):
                self._normalize_block_hash(value)
            else:
                self._normalize_block_tag(value)
            params[0] = self._pinned_block_hash
        elif method == "eth_getLogs":
            self._pin_log_filter(params)

    def _normalize_block_tag(self, value: object) -> str:
        if isinstance(value, str) and value in _PINNED_SYMBOLIC_TAGS:
            return self._pinned_block_tag
        if value == "earliest" and self._pinned_block_number == 0:
            return self._pinned_block_tag
        if (
            isinstance(value, str)
            and _BLOCK_TAG_PATTERN.fullmatch(value)
            and value == self._pinned_block_tag
        ):
            return value
        raise _BridgeRejection(_RejectionKind.DENIED)

    def _normalize_block_reference(self, value: object) -> dict[str, object]:
        if isinstance(value, dict):
            if (
                set(value) != {"blockHash", "requireCanonical"}
                or value.get("blockHash") != self._pinned_block_hash
                or value.get("requireCanonical") is not True
            ):
                raise _BridgeRejection(_RejectionKind.DENIED)
        else:
            self._normalize_block_tag(value)
        return self._canonical_block_reference()

    def _canonical_block_reference(self) -> dict[str, object]:
        return {
            "blockHash": self._pinned_block_hash,
            "requireCanonical": True,
        }

    def _normalize_block_hash(self, value: object) -> str:
        if value != self._pinned_block_hash:
            raise _BridgeRejection(_RejectionKind.DENIED)
        return self._pinned_block_hash

    def _pin_log_filter(self, params: list[object]) -> None:
        if len(params) != 1 or not isinstance(params[0], dict):
            raise _BridgeRejection(_RejectionKind.MALFORMED)
        filter_value = cast(dict[str, object], params[0])
        if "blockHash" in filter_value:
            if "fromBlock" in filter_value or "toBlock" in filter_value:
                raise _BridgeRejection(_RejectionKind.MALFORMED)
            filter_value["blockHash"] = self._normalize_block_hash(filter_value["blockHash"])
            return
        self._normalize_block_tag(filter_value.get("fromBlock", "latest"))
        self._normalize_block_tag(filter_value.get("toBlock", "latest"))
        filter_value.pop("fromBlock", None)
        filter_value.pop("toBlock", None)
        filter_value["blockHash"] = self._pinned_block_hash

    def _serialize_outbound(
        self,
        outbound_calls: list[_PreparedCall],
        *,
        is_batch: bool,
    ) -> bytes:
        if not outbound_calls:
            return b""
        payload: object
        if is_batch:
            payload = [call.payload for call in outbound_calls]
        else:
            payload = outbound_calls[0].payload
        body = _encode_json(payload)
        if len(body) > self._max_request_body_bytes:
            raise _BridgeRejection(_RejectionKind.LIMIT)
        return body

    def _admit_http_request(self, accept_generation: int) -> tuple[bool, bool]:
        """Hard-saturate the HTTP budget and signal permanent admission closure."""

        with self._scope_boundary_lock, self._scope_drain_condition:
            if self._pending_accepted_http_request_count < 1:
                raise ReadOnlyRpcBridgeError(
                    "read-only RPC accepted request accounting is inconsistent"
                )
            self._pending_accepted_http_request_count -= 1
            self._scope_drain_condition.notify_all()
            if self._admission_closed or accept_generation != self._accept_generation:
                self._http_request_count += 1
                self._limit_exceeded_request_count += 1
                return False, False
            if self._http_admission_saturated:
                return False, True
            self._http_request_count += 1
            self._inflight_admitted_http_request_count += 1
            active_scope = self._active_test_scope
            if active_scope is not None:
                active_scope.http_request_count += 1
            self._http_admission_saturated = self._http_request_count == self._max_http_requests
            return True, self._http_admission_saturated

    def _finish_admitted_http_request(self) -> None:
        with self._scope_drain_condition:
            if self._inflight_admitted_http_request_count < 1:
                raise ReadOnlyRpcBridgeError(
                    "read-only RPC admitted request accounting is inconsistent"
                )
            self._inflight_admitted_http_request_count -= 1
            self._scope_drain_condition.notify_all()

    def _record_permitted(
        self,
        prepared: list[_PreparedCall],
        *,
        origin_attempted_count: int,
    ) -> None:
        with self._state_lock:
            if self._permitted_rpc_call_count + len(prepared) > self._max_rpc_calls:
                raise _BridgeRejection(_RejectionKind.LIMIT)
            self._permitted_rpc_call_count += len(prepared)
            self._origin_attempted_rpc_call_count += origin_attempted_count
            self._synthetic_rpc_call_count += len(prepared) - origin_attempted_count
            active_scope = self._active_test_scope
            if active_scope is not None:
                active_scope.permitted_rpc_call_count += len(prepared)
                active_scope.origin_attempted_rpc_call_count += origin_attempted_count
                active_scope.synthetic_rpc_call_count += len(prepared) - origin_attempted_count
            for call in prepared:
                self._allowed_method_counts[call.method] = (
                    self._allowed_method_counts.get(call.method, 0) + 1
                )
                self._method_log.append(call.method)
                if active_scope is not None:
                    active_scope.allowed_method_counts[call.method] = (
                        active_scope.allowed_method_counts.get(call.method, 0) + 1
                    )
                    active_scope.method_log.append(call.method)

    def _record_origin_validated(self, validated_count: int) -> None:
        with self._state_lock:
            self._origin_validated_rpc_call_count += validated_count
            if self._active_test_scope is not None:
                self._active_test_scope.origin_validated_rpc_call_count += validated_count

    def _forward(
        self,
        outbound_body: bytes,
        outbound_calls: list[_PreparedCall],
        *,
        is_batch: bool,
    ) -> dict[tuple[type[int] | type[str], int | str], dict[str, object]]:
        operation_id = self._begin_upstream_operation()
        connection = HTTPConnection(
            self._origin_host,
            self._origin_port,
            timeout=self._timeout_seconds,
        )
        body = bytearray()
        try:
            try:
                connection.connect()
                transport_socket = connection.sock
                if transport_socket is None:
                    raise _BridgeRejection(_RejectionKind.UPSTREAM)
                self._register_upstream_socket(operation_id, transport_socket)
                connection.request(
                    "POST",
                    "/",
                    body=outbound_body,
                    headers={"Content-Type": "application/json"},
                )
                response = connection.getresponse()
                if response.status != 200:
                    raise _BridgeRejection(_RejectionKind.UPSTREAM)
                content_lengths = [
                    value
                    for name, value in response.getheaders()
                    if name.lower() == "content-length"
                ]
                if len(content_lengths) > 1 or (
                    content_lengths
                    and (
                        not content_lengths[0].isdigit()
                        or int(content_lengths[0]) > self._max_response_body_bytes
                    )
                ):
                    raise _BridgeRejection(_RejectionKind.UPSTREAM)
                while True:
                    chunk = response.read(65_536)
                    if not chunk:
                        break
                    body.extend(chunk)
                    if len(body) > self._max_response_body_bytes:
                        raise _BridgeRejection(_RejectionKind.UPSTREAM)
            except _BridgeRejection:
                raise
            except (HTTPException, OSError, TimeoutError):
                raise _BridgeRejection(_RejectionKind.UPSTREAM) from None
        finally:
            with suppress(OSError):
                connection.close()
            self._end_upstream_operation(operation_id)
        payload = _strict_json(
            bytes(body),
            max_depth=self._max_json_depth,
            max_nodes=self._max_json_nodes,
            failure_kind=_RejectionKind.UPSTREAM,
        )
        return _validate_upstream_responses(
            payload,
            outbound_calls,
            is_batch=is_batch,
            pinned_block_tag=self._pinned_block_tag,
            pinned_block_hash=self._pinned_block_hash,
        )

    def _begin_upstream_operation(self) -> object:
        operation_id = object()
        with self._active_upstream_lock:
            if self._upstream_shutdown_requested:
                raise _BridgeRejection(_RejectionKind.UPSTREAM)
            self._active_upstream_connections[operation_id] = None
        return operation_id

    def _register_upstream_socket(
        self,
        operation_id: object,
        transport_socket: socket.socket,
    ) -> None:
        with self._active_upstream_lock:
            if operation_id not in self._active_upstream_connections:
                raise _BridgeRejection(_RejectionKind.UPSTREAM)
            self._active_upstream_connections[operation_id] = transport_socket
            shutdown_requested = self._upstream_shutdown_requested
        if shutdown_requested:
            _close_connection(transport_socket)

    def _end_upstream_operation(self, operation_id: object) -> None:
        with self._active_upstream_lock:
            self._active_upstream_connections.pop(operation_id, None)

    def _upstream_resources_drained(self) -> bool:
        with self._active_upstream_lock:
            return not self._active_upstream_connections

    def _close_active_upstream_responses(self) -> None:
        with self._active_upstream_lock:
            self._upstream_shutdown_requested = True
            transport_sockets = tuple(
                transport_socket
                for transport_socket in self._active_upstream_connections.values()
                if transport_socket is not None
            )
        for transport_socket in transport_sockets:
            _close_connection(transport_socket)

    def _combine_responses(
        self,
        prepared: list[_PreparedCall],
        upstream: dict[tuple[type[int] | type[str], int | str], dict[str, object]],
        *,
        is_batch: bool,
    ) -> object:
        combined: list[dict[str, object]] = []
        for call in prepared:
            if call.is_synthetic:
                combined.append(
                    {
                        "jsonrpc": "2.0",
                        "id": call.request_id,
                        "result": call.synthetic_result,
                    }
                )
            else:
                response = upstream.get(_rpc_id_key(call.request_id))
                if response is None:
                    raise _BridgeRejection(_RejectionKind.UPSTREAM)
                combined.append(response)
        return combined if is_batch else combined[0]

    def _record_rejection(self, kind: _RejectionKind) -> None:
        with self._state_lock:
            if kind is _RejectionKind.DENIED:
                self._denied_request_count += 1
                if self._active_test_scope is not None:
                    self._active_test_scope.denied_request_count += 1
            elif kind is _RejectionKind.MALFORMED:
                self._malformed_request_count += 1
                if self._active_test_scope is not None:
                    self._active_test_scope.malformed_request_count += 1
            elif kind is _RejectionKind.LIMIT:
                self._limit_exceeded_request_count += 1
                if self._active_test_scope is not None:
                    self._active_test_scope.limit_exceeded_request_count += 1
            else:
                self._upstream_error_request_count += 1
                if self._active_test_scope is not None:
                    self._active_test_scope.upstream_error_request_count += 1

    def _write_rejection(
        self,
        handler: _BridgeRequestHandler,
        kind: _RejectionKind,
    ) -> None:
        status_code = {
            _RejectionKind.DENIED: 403,
            _RejectionKind.LIMIT: 413,
            _RejectionKind.MALFORMED: 400,
            _RejectionKind.UPSTREAM: 502,
        }[kind]
        body = _encode_json(
            {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": "read-only RPC policy rejected request",
                },
            }
        )
        self._write_response(handler, status_code, body)

    @staticmethod
    def _write_response(
        handler: _BridgeRequestHandler,
        status_code: int,
        body: bytes,
    ) -> None:
        handler.close_connection = True
        try:
            handler.send_response(status_code)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(body)))
            handler.send_header("Cache-Control", "no-store")
            handler.send_header("Connection", "close")
            handler.end_headers()
            handler.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return


def _validate_upstream_responses(
    payload: object,
    outbound_calls: list[_PreparedCall],
    *,
    is_batch: bool,
    pinned_block_tag: str,
    pinned_block_hash: str,
) -> dict[tuple[type[int] | type[str], int | str], dict[str, object]]:
    if is_batch:
        if not isinstance(payload, list) or len(payload) != len(outbound_calls):
            raise _BridgeRejection(_RejectionKind.UPSTREAM)
        responses = payload
    else:
        if not isinstance(payload, dict) or len(outbound_calls) != 1:
            raise _BridgeRejection(_RejectionKind.UPSTREAM)
        responses = [payload]
    expected_calls = {_rpc_id_key(call.request_id): call for call in outbound_calls}
    expected_ids = set(expected_calls)
    result: dict[tuple[type[int] | type[str], int | str], dict[str, object]] = {}
    for item in responses:
        if not isinstance(item, dict):
            raise _BridgeRejection(_RejectionKind.UPSTREAM)
        if item.get("jsonrpc") != "2.0" or not _valid_rpc_id(item.get("id")):
            raise _BridgeRejection(_RejectionKind.UPSTREAM)
        if not {"jsonrpc", "id"} <= item.keys() or not set(item) <= {
            "jsonrpc",
            "id",
            "result",
            "error",
        }:
            raise _BridgeRejection(_RejectionKind.UPSTREAM)
        if ("result" in item) == ("error" in item):
            raise _BridgeRejection(_RejectionKind.UPSTREAM)
        response_id = cast(int | str, item["id"])
        response_key = _rpc_id_key(response_id)
        if response_key not in expected_ids or response_key in result:
            raise _BridgeRejection(_RejectionKind.UPSTREAM)
        if "error" in item:
            if not _valid_rpc_error(item["error"]):
                raise _BridgeRejection(_RejectionKind.UPSTREAM)
            # A well-formed JSON-RPC error is still an unsuccessful origin read.
            # It must never be relayed as evidence that the read policy was enforced.
            raise _BridgeRejection(_RejectionKind.UPSTREAM)
        _validate_origin_result(
            expected_calls[response_key],
            item["result"],
            pinned_block_tag=pinned_block_tag,
            pinned_block_hash=pinned_block_hash,
        )
        result[response_key] = cast(dict[str, object], item)
    if set(result) != expected_ids:
        raise _BridgeRejection(_RejectionKind.UPSTREAM)
    return result


def _validate_origin_result(
    call: _PreparedCall,
    value: object,
    *,
    pinned_block_tag: str,
    pinned_block_hash: str,
) -> None:
    if call.method in _QUANTITY_RESULT_METHODS:
        if not _is_rpc_quantity(value):
            raise _BridgeRejection(_RejectionKind.UPSTREAM)
        return
    if call.method in _BYTE_RESULT_METHODS:
        if not _is_hex_bytes(value):
            raise _BridgeRejection(_RejectionKind.UPSTREAM)
        return
    if call.method == "eth_getStorageAt":
        if not isinstance(value, str) or re.fullmatch(r"0x[0-9a-f]{64}", value) is None:
            raise _BridgeRejection(_RejectionKind.UPSTREAM)
        return
    if call.method in {"eth_getBlockByHash", "eth_getBlockByNumber"}:
        if (
            not isinstance(value, dict)
            or value.get("number") != pinned_block_tag
            or value.get("hash") != pinned_block_hash
        ):
            raise _BridgeRejection(_RejectionKind.UPSTREAM)
        return
    if call.method in {"eth_getBlockReceipts", "eth_getLogs"}:
        if not isinstance(value, list) or any(
            not _has_exact_block_provenance(item, pinned_block_tag, pinned_block_hash)
            or (
                call.method == "eth_getLogs"
                and isinstance(item, dict)
                and item.get("removed", False) is not False
            )
            for item in value
        ):
            raise _BridgeRejection(_RejectionKind.UPSTREAM)
        return
    if call.method in {
        "eth_getTransactionByBlockHashAndIndex",
        "eth_getTransactionByBlockNumberAndIndex",
    }:
        if value is not None and not _has_exact_block_provenance(
            value,
            pinned_block_tag,
            pinned_block_hash,
        ):
            raise _BridgeRejection(_RejectionKind.UPSTREAM)
        return
    if call.method in {
        "eth_getUncleByBlockHashAndIndex",
        "eth_getUncleByBlockNumberAndIndex",
    }:
        if value is not None and (
            not isinstance(value, dict)
            or not _is_rpc_quantity(value.get("number"))
            or not isinstance(value.get("hash"), str)
            or _BLOCK_HASH_PATTERN.fullmatch(cast(str, value["hash"])) is None
        ):
            raise _BridgeRejection(_RejectionKind.UPSTREAM)
        return
    raise _BridgeRejection(_RejectionKind.UPSTREAM)


def _has_exact_block_provenance(
    value: object,
    pinned_block_tag: str,
    pinned_block_hash: str,
) -> bool:
    return (
        isinstance(value, dict)
        and value.get("blockNumber") == pinned_block_tag
        and value.get("blockHash") == pinned_block_hash
    )


def _is_exact_pinned_block(
    value: object,
    pinned_block_tag: str,
    pinned_block_hash: str,
) -> bool:
    return (
        isinstance(value, dict)
        and value.get("number") == pinned_block_tag
        and value.get("hash") == pinned_block_hash
    )


def _is_rpc_quantity(value: object) -> bool:
    return isinstance(value, str) and _BLOCK_TAG_PATTERN.fullmatch(value) is not None


def _rpc_quantity_to_int(value: object) -> int:
    if not _is_rpc_quantity(value):
        raise ReadOnlyRpcBridgeError("origin identity quantity is invalid")
    parsed = int(cast(str, value), 16)
    if not 0 <= parsed < 2**64:
        raise ReadOnlyRpcBridgeError("origin identity quantity is invalid")
    return parsed


def _is_hex_bytes(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("0x"):
        return False
    encoded = value[2:]
    return len(encoded) % 2 == 0 and re.fullmatch(r"[0-9a-f]*", encoded) is not None


def _close_connection(request: socket.socket) -> None:
    with suppress(OSError):
        request.shutdown(socket.SHUT_RDWR)
    with suppress(OSError):
        request.close()


def _reject_capacity_connection(request: socket.socket) -> None:
    body = _encode_json(
        {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": -32600,
                "message": "read-only RPC policy rejected request",
            },
        }
    )
    response = (
        b"HTTP/1.1 503 Service Unavailable\r\n"
        b"Content-Type: application/json\r\n"
        b"Cache-Control: no-store\r\n"
        b"Connection: close\r\n" + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body
    )
    try:
        request.sendall(response)
        request.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    finally:
        request.close()


def _valid_rpc_error(value: object) -> bool:
    if not isinstance(value, dict) or not {"code", "message"} <= value.keys():
        return False
    if not set(value) <= {"code", "message", "data"}:
        return False
    code = value["code"]
    message = value["message"]
    return (
        isinstance(code, int)
        and not isinstance(code, bool)
        and -(2**31) <= code < 2**31
        and isinstance(message, str)
        and len(message) <= 2_000
    )


def _valid_rpc_id(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return -(2**63) <= value < 2**63
    return (
        isinstance(value, str)
        and 0 < len(value) <= _MAX_RPC_ID_TEXT_LENGTH
        and all(ord(character) >= 32 and ord(character) != 127 for character in value)
    )


def _rpc_id_key(value: int | str) -> tuple[type[int] | type[str], int | str]:
    return (type(value), value)


def _strict_json(
    body: bytes,
    *,
    max_depth: int,
    max_nodes: int,
    failure_kind: _RejectionKind,
) -> object:
    try:
        text = body.decode("utf-8", errors="strict")
        if text.startswith("\ufeff"):
            raise UnicodeDecodeError("utf-8", body, 0, 1, "BOM is not accepted")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateKeyError,
        RecursionError,
        ValueError,
    ):
        raise _BridgeRejection(failure_kind) from None
    _validate_json_shape(
        value,
        max_depth=max_depth,
        max_nodes=max_nodes,
        failure_kind=failure_kind,
    )
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _validate_json_shape(
    value: object,
    *,
    max_depth: int,
    max_nodes: int,
    failure_kind: _RejectionKind,
) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > max_depth or nodes > max_nodes:
            raise _BridgeRejection(
                _RejectionKind.LIMIT if failure_kind is _RejectionKind.MALFORMED else failure_kind
            )
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def _encode_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_encode_json(value)).hexdigest()


def _validate_test_scope_identity(
    *,
    attempt_binding_sha256: str,
    selection_sha256: str,
    descriptor_sha256: str,
    sequence_index: int,
) -> tuple[str, str, str, int]:
    if (
        _SHA256_PATTERN.fullmatch(attempt_binding_sha256) is None
        or _SHA256_PATTERN.fullmatch(selection_sha256) is None
        or _SHA256_PATTERN.fullmatch(descriptor_sha256) is None
        or type(sequence_index) is not int
        or not 1 <= sequence_index <= 10_000
    ):
        raise ReadOnlyRpcBridgeError("read-only RPC selected test scope identity is invalid")
    return (
        attempt_binding_sha256,
        selection_sha256,
        descriptor_sha256,
        sequence_index,
    )


def _require_bound(label: str, value: int, *, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not minimum <= value <= maximum:
        raise ReadOnlyRpcBridgeError(f"read-only RPC {label} is outside the supported range")


def _numeric_loopback_endpoint(value: str) -> str:
    port = local_fork_rpc_port(value)
    host = urlparse(value).hostname
    if host in {"127.0.0.1", "localhost"}:
        return f"http://127.0.0.1:{port}"
    if host == "::1":
        return f"http://[::1]:{port}"
    raise ForkRpcBindingError("read-only RPC origin is not a numeric loopback endpoint")
