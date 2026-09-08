"""Pinned, incomplete offline RPC read data; no listener, upstream or execution authority."""

from __future__ import annotations

import hashlib
import re
import threading
from pathlib import Path
from types import MappingProxyType
from typing import Literal, Self

from pydantic import ConfigDict, Field, JsonValue, field_validator, model_validator

from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import read_file_evidence
from mmaudit.scanners.fork_rpc import PinnedForkObservation
from mmaudit.scanners.read_only_rpc import (
    _SYNTHETIC_METHODS,
    READ_ONLY_RPC_METHODS,
    _BridgeRejection,
    _encode_json,
    _PinnedRpcReadPolicy,
    _RejectionKind,
    _strict_json,
    _validate_origin_result,
)

_MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
_MAX_ARCHIVE_READS = 4096
_MAX_REQUEST_BYTES = 1024 * 1024
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_REQUESTS = 10_000
_MAX_CALLS = 100_000
_MAX_JSON_DEPTH = 32
_MAX_ARCHIVE_NODES = 250_000
_MAX_REQUEST_NODES = 100_000
_SHA256 = r"^[0-9a-f]{64}$"
_OFFLINE_ARCHIVE_ADMISSION = object()


class OfflineForkRpcError(ValueError):
    """Offline data is invalid, exhausted or unavailable; never substitute live or zero state."""


class OfflineForkRpcRead(StrictModel):
    """One supplied canonical hash-bound read, not a cryptographic state proof."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: str = Field(
        strict=True,
        min_length=1,
        max_length=64,
        json_schema_extra={
            "enum": [method for method in sorted(READ_ONLY_RPC_METHODS - _SYNTHETIC_METHODS)]
        },
    )
    params: tuple[JsonValue, ...] = Field(max_length=64)
    result: JsonValue


class OfflineForkRpcArchive(StrictModel):
    """Strict offline input declaration; provenance and state completeness are not attested."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    artifact_kind: Literal["MMAUDIT_OFFLINE_FORK_RPC_ARCHIVE"]
    source_kind: Literal["SYNTHETIC_FIXTURE", "OPERATOR_SUPPLIED_OFFLINE"]
    chain_id: int = Field(strict=True, ge=1, lt=2**64)
    block_number: int = Field(strict=True, ge=0, lt=2**64)
    block_hash: str = Field(strict=True, pattern=r"^0x[0-9a-f]{64}$")
    complete_state: Literal[False]
    runtime_authority: Literal[False]
    reads: tuple[OfflineForkRpcRead, ...] = Field(min_length=1, max_length=_MAX_ARCHIVE_READS)

    @field_validator("complete_state", "runtime_authority", mode="before")
    @classmethod
    def claims_are_literal_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("offline archive claims must be literal false")
        return value

    @model_validator(mode="after")
    def reads_are_canonical_and_consistent(self) -> Self:
        policy = _PinnedRpcReadPolicy(
            expected_chain_id=self.chain_id,
            pinned_block_number=self.block_number,
            pinned_block_hash=self.block_hash,
        )
        if self.block_hash == "0x" + "0" * 64:
            raise ValueError("offline archive block hash must be nonzero")
        keys: set[bytes] = set()
        account_values: dict[tuple[str, str], bytes] = {}
        identity_key = _read_key("eth_getBlockByHash", [self.block_hash, False])
        for row in self.reads:
            values = row.model_dump(mode="json")
            try:
                call = policy._prepare_call(
                    {"jsonrpc": "2.0", "id": 1, "method": row.method, "params": values["params"]}
                )
                if (
                    call.is_synthetic
                    or call.origin_method != row.method
                    or call.payload["params"] != values["params"]
                ):
                    raise ValueError("offline archive read is not canonical")
                _validate_origin_result(
                    call,
                    values["result"],
                    pinned_block_tag=hex(self.block_number),
                    pinned_block_hash=self.block_hash,
                )
                if len(_encode_json(values["result"])) > _MAX_RESPONSE_BYTES:
                    raise ValueError("offline archive result exceeds its bound")
                _join_account_reads(row.method, values["params"], values["result"], account_values)
                key = _read_key(row.method, values["params"])
            except _BridgeRejection:
                raise ValueError(
                    "offline archive read violates the pinned read-only policy"
                ) from None
            if key in keys:
                raise ValueError("offline archive has duplicate or contradictory read identities")
            keys.add(key)
        if identity_key not in keys:
            raise ValueError("offline archive lacks the pinned block identity read")
        return self


def _read_key(method: str, params: object) -> bytes:
    return _encode_json({"method": method, "params": params})


def _join_account_reads(
    method: str,
    params: list[JsonValue],
    result: JsonValue,
    observed: dict[tuple[str, str], bytes],
) -> None:
    """Reject contradictory recorded account fields; this does not prove state-root correctness."""

    fields = {
        "eth_getBalance": "balance",
        "eth_getCode": "code",
        "eth_getTransactionCount": "nonce",
        "eth_getStorageAt": "storage",
        "eth_getAccountInfo": "account",
    }
    field = fields.get(method)
    if field is None:
        return
    address = params[0]
    if not isinstance(address, str) or re.fullmatch(r"0x[0-9a-f]{40}", address) is None:
        raise ValueError("offline archive account address is not canonical")
    if method == "eth_getStorageAt":
        slot = params[1]
        if (
            not isinstance(slot, str)
            or re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]{0,63})", slot) is None
        ):
            raise ValueError("offline archive storage slot is not canonical")
        field = "storage:" + slot
    values = (
        result if method == "eth_getAccountInfo" and isinstance(result, dict) else {field: result}
    )
    for name, value in values.items():
        key = (address, name)
        encoded = _encode_json(value)
        previous = observed.setdefault(key, encoded)
        if previous != encoded:
            raise ValueError("offline archive account reads contradict one another")


class OfflineForkRpcReplay:
    """Replay a fixed in-memory snapshot with bounded, atomic requests and no external I/O."""

    def __init__(
        self,
        *,
        root: Path,
        relative_path: str | Path,
        content: bytes,
        binding: ManifestFileBinding,
        archive: OfflineForkRpcArchive,
        max_requests: int,
        max_calls: int,
        _admission: object | None = None,
    ) -> None:
        if _admission is not _OFFLINE_ARCHIVE_ADMISSION:
            raise OfflineForkRpcError("offline replay requires pinned archive admission")
        self._root = root
        self._relative_path = relative_path
        self._content = content
        self._binding = binding.model_copy(deep=True)
        self._observation = PinnedForkObservation(
            chain_id=archive.chain_id,
            block_number=archive.block_number,
            block_hash=archive.block_hash,
        )
        self._policy = _PinnedRpcReadPolicy(
            expected_chain_id=archive.chain_id,
            pinned_block_number=archive.block_number,
            pinned_block_hash=archive.block_hash,
        )
        self._reads = MappingProxyType(
            {
                _read_key(row.method, row.model_dump(mode="json")["params"]): _encode_json(
                    row.result
                )
                for row in archive.reads
            }
        )
        self._max_requests = max_requests
        self._max_calls = max_calls
        self._request_count = 0
        self._call_count = 0
        self._lock = threading.Lock()

    @property
    def source_binding(self) -> ManifestFileBinding:
        return self._binding.model_copy(deep=True)

    @property
    def observation(self) -> PinnedForkObservation:
        return self._observation

    @property
    def runtime_authority(self) -> Literal[False]:
        return False

    @property
    def complete_state(self) -> Literal[False]:
        return False

    def verify_source(self) -> None:
        """Explicitly reverify the input; replay itself uses only previously frozen bytes."""

        try:
            current = read_file_evidence(
                evidence_root=self._root,
                relative_path=self._relative_path,
                max_bytes=_MAX_ARCHIVE_BYTES,
            )
            if current.binding != self._binding or current.content != self._content:
                raise ValueError("archive changed")
        except (OSError, RuntimeError, ValueError):
            raise OfflineForkRpcError("offline archive source verification failed") from None

    def respond(self, body: bytes) -> bytes:
        """Return only recorded reads or explicit identity constants; missing batches fail whole."""

        with self._lock:
            if self._request_count >= self._max_requests:
                raise OfflineForkRpcError("offline replay request budget exhausted")
            self._request_count += 1
            if type(body) is not bytes or not 2 <= len(body) <= _MAX_REQUEST_BYTES:
                raise OfflineForkRpcError("offline replay request exceeds its fixed bound")
            try:
                payload = _strict_json(
                    body,
                    max_depth=_MAX_JSON_DEPTH,
                    max_nodes=_MAX_REQUEST_NODES,
                    failure_kind=_RejectionKind.MALFORMED,
                )
                calls, batch = self._policy._prepare_payload(payload)
                if self._call_count + len(calls) > self._max_calls:
                    self._call_count = self._max_calls
                    raise OfflineForkRpcError("offline replay call budget exhausted")
                self._call_count += len(calls)
                responses: list[bytes] = []
                response_size = 2 if batch else 0
                for call in calls:
                    if call.is_synthetic:
                        stored = _encode_json(call.synthetic_result)
                    else:
                        stored_read = self._reads.get(
                            _read_key(call.origin_method, call.payload["params"])
                        )
                        if stored_read is None:
                            raise OfflineForkRpcError("offline replay required read is unavailable")
                        stored = stored_read
                    prefix = _encode_json({"jsonrpc": "2.0", "id": call.request_id})[:-1]
                    response = prefix + b',"result":' + stored + b"}"
                    response_size += len(response) + (1 if responses and batch else 0)
                    if response_size > _MAX_RESPONSE_BYTES:
                        raise OfflineForkRpcError("offline replay response exceeds its fixed bound")
                    responses.append(response)
                return b"[" + b",".join(responses) + b"]" if batch else responses[0]
            except (_BridgeRejection, RecursionError, TypeError, ValueError):
                raise OfflineForkRpcError(
                    "offline replay request is invalid or unavailable"
                ) from None


def load_offline_fork_rpc_archive(
    root: Path,
    relative_path: str | Path,
    *,
    expected_sha256: str,
    expected_chain_id: int,
    pinned_block_number: int,
    max_requests: int = _MAX_REQUESTS,
    max_calls: int = _MAX_CALLS,
) -> OfflineForkRpcReplay:
    """Load only bounded stable pinned local bytes; declarations never attest source or execution."""

    if (
        not isinstance(root, Path)
        or not root.is_absolute()
        or ".." in root.parts
        or type(expected_sha256) is not str
        or re.fullmatch(_SHA256, expected_sha256) is None
        or expected_sha256 == "0" * 64
        or type(expected_chain_id) is not int
        or not 1 <= expected_chain_id < 2**64
        or type(pinned_block_number) is not int
        or not 0 <= pinned_block_number < 2**64
        or type(max_requests) is not int
        or not 1 <= max_requests <= _MAX_REQUESTS
        or type(max_calls) is not int
        or not 1 <= max_calls <= _MAX_CALLS
    ):
        raise OfflineForkRpcError("offline archive pins or replay bounds are invalid")
    try:
        observation = read_file_evidence(
            evidence_root=root, relative_path=relative_path, max_bytes=_MAX_ARCHIVE_BYTES
        )
        if observation.binding.sha256 != expected_sha256:
            raise ValueError("archive pin differs")
        payload = _strict_json(
            observation.content,
            max_depth=_MAX_JSON_DEPTH,
            max_nodes=_MAX_ARCHIVE_NODES,
            failure_kind=_RejectionKind.MALFORMED,
        )
        archive = OfflineForkRpcArchive.model_validate(payload)
        if archive.chain_id != expected_chain_id or archive.block_number != pinned_block_number:
            raise ValueError("archive state differs")
        # Validate all JSON scalar values too, including overflowing floating-point values.
        _encode_json(archive.model_dump(mode="json"))
        if hashlib.sha256(observation.content).hexdigest() != expected_sha256:
            raise ValueError("archive content differs")
        return OfflineForkRpcReplay(
            root=root,
            relative_path=relative_path,
            content=observation.content,
            binding=observation.binding,
            archive=archive,
            max_requests=max_requests,
            max_calls=max_calls,
            _admission=_OFFLINE_ARCHIVE_ADMISSION,
        )
    except (OSError, RuntimeError, ValueError, TypeError, _BridgeRejection):
        raise OfflineForkRpcError("offline fork archive failed pinned input validation") from None
