"""Bounded read-only identity checks for an operator-pinned loopback fork."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

_MAX_RPC_RESPONSE_BYTES = 65_536
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class ForkRpcUnavailableError(RuntimeError):
    """The approved loopback endpoint could not be queried."""


class ForkRpcBindingError(ValueError):
    """The endpoint response did not match the required fork identity."""


@dataclass(frozen=True)
class PinnedForkObservation:
    """Observed identity of one exact block on the configured local fork."""

    chain_id: int
    block_number: int
    block_hash: str


def local_fork_rpc_port(endpoint: str) -> int:
    """Validate an exact credential-free loopback HTTP endpoint and return its port."""

    parsed = urlparse(endpoint)
    if (
        parsed.scheme != "http"
        or not parsed.netloc
        or parsed.hostname not in _LOOPBACK_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ForkRpcBindingError("fork RPC must be a credential-free loopback HTTP endpoint")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ForkRpcBindingError("fork RPC port is invalid") from exc
    if port is None:
        raise ForkRpcBindingError("fork RPC must contain an explicit port")
    return port


def observe_pinned_fork_rpc(
    endpoint: str,
    *,
    expected_chain_id: int | None,
    pinned_block_number: int | None,
    timeout_seconds: float = 5.0,
    client: httpx.Client | None = None,
) -> PinnedForkObservation:
    """Read and validate one exact block without executing repository code."""

    local_fork_rpc_port(endpoint)
    if expected_chain_id is None or pinned_block_number is None:
        raise ForkRpcBindingError(
            "repository fork-suite execution requires a pinned chain ID and block number"
        )
    if expected_chain_id < 1 or pinned_block_number < 0:
        raise ForkRpcBindingError("pinned fork identity is outside the supported range")

    owns_client = client is None
    rpc_client = client or httpx.Client(
        timeout=httpx.Timeout(timeout_seconds),
        follow_redirects=False,
        trust_env=False,
    )
    try:
        observed_chain_id = _hex_quantity(
            _rpc(rpc_client, endpoint, request_id=1, method="eth_chainId", params=[]),
            "chain ID",
        )
        block = _rpc(
            rpc_client,
            endpoint,
            request_id=2,
            method="eth_getBlockByNumber",
            params=[hex(pinned_block_number), False],
        )
    except httpx.RequestError as exc:
        raise ForkRpcUnavailableError("configured loopback fork RPC is unavailable") from exc
    finally:
        if owns_client:
            rpc_client.close()

    if observed_chain_id != expected_chain_id:
        raise ForkRpcBindingError("observed fork chain ID does not match the configured pin")
    if not isinstance(block, dict):
        raise ForkRpcBindingError("pinned fork block response is malformed")
    observed_block_number = _hex_quantity(block.get("number"), "block number")
    block_hash = block.get("hash")
    if (
        observed_block_number != pinned_block_number
        or not isinstance(block_hash, str)
        or len(block_hash) != 66
        or not block_hash.startswith("0x")
    ):
        raise ForkRpcBindingError("observed fork block does not match the configured pin")
    try:
        bytes.fromhex(block_hash[2:])
    except ValueError as exc:
        raise ForkRpcBindingError("observed fork block hash is malformed") from exc
    return PinnedForkObservation(
        chain_id=observed_chain_id,
        block_number=observed_block_number,
        block_hash=block_hash.lower(),
    )


def _rpc(
    client: httpx.Client,
    endpoint: str,
    *,
    request_id: int,
    method: str,
    params: list[object],
) -> Any:
    with client.stream(
        "POST",
        endpoint,
        json={
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        },
    ) as response:
        if response.status_code != 200:
            raise ForkRpcUnavailableError(
                "configured loopback fork RPC returned an unsuccessful status"
            )
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > _MAX_RPC_RESPONSE_BYTES:
                raise ForkRpcBindingError("fork RPC response exceeded the fixed size bound")
    try:
        payload = json.loads(
            body,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as exc:
        raise ForkRpcBindingError("fork RPC response was not strict JSON") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("jsonrpc") != "2.0"
        or payload.get("id") != request_id
        or "error" in payload
        or "result" not in payload
    ):
        raise ForkRpcBindingError("fork RPC response envelope is invalid")
    return payload["result"]


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ForkRpcBindingError("fork RPC response contains duplicate keys")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ForkRpcBindingError(f"fork RPC response contains invalid number {value!r}")


def _hex_quantity(value: Any, label: str) -> int:
    if (
        not isinstance(value, str)
        or not value.startswith("0x")
        or value == "0x"
        or (len(value) > 3 and value[2] == "0")
    ):
        raise ForkRpcBindingError(f"fork RPC {label} is not a canonical hex quantity")
    try:
        number = int(value[2:], 16)
    except ValueError as exc:
        raise ForkRpcBindingError(f"fork RPC {label} is malformed") from exc
    if number < 0 or number >= 2**256:
        raise ForkRpcBindingError(f"fork RPC {label} is outside the supported range")
    return number
