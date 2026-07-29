from __future__ import annotations

import json

import httpx
import pytest

from mmaudit.scanners.fork_rpc import (
    ForkRpcBindingError,
    ForkRpcUnavailableError,
    local_fork_rpc_port,
    observe_pinned_fork_rpc,
)


def _client(
    *,
    chain_id: str = "0x7a69",
    block_number: str = "0x2a",
    block_hash: str = "0x" + "ab" * 32,
) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        result: object
        if payload["method"] == "eth_chainId":
            result = chain_id
        else:
            result = {"number": block_number, "hash": block_hash}
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": payload["id"], "result": result},
        )

    return httpx.Client(
        transport=httpx.MockTransport(handler),
        trust_env=False,
        follow_redirects=False,
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:8545",
        "http://example.invalid:8545",
        "http://user:pass@127.0.0.1:8545",
        "http://127.0.0.1:8545/rpc",
        "http://127.0.0.1:8545/?token=secret",
        "http://127.0.0.1",
    ],
)
def test_local_fork_rpc_rejects_non_exact_loopback_endpoint(endpoint: str) -> None:
    with pytest.raises(ForkRpcBindingError):
        local_fork_rpc_port(endpoint)


def test_observe_pinned_fork_rpc_binds_chain_block_and_hash() -> None:
    with _client() as client:
        observation = observe_pinned_fork_rpc(
            "http://127.0.0.1:8545",
            expected_chain_id=31_337,
            pinned_block_number=42,
            client=client,
        )

    assert observation.chain_id == 31_337
    assert observation.block_number == 42
    assert observation.block_hash == "0x" + "ab" * 32


def test_observe_pinned_fork_rpc_requires_both_operator_pins() -> None:
    with (
        _client() as client,
        pytest.raises(ForkRpcBindingError, match="pinned chain ID and block"),
    ):
        observe_pinned_fork_rpc(
            "http://127.0.0.1:8545",
            expected_chain_id=None,
            pinned_block_number=42,
            client=client,
        )


def test_observe_pinned_fork_rpc_rejects_identity_mismatch() -> None:
    with (
        _client(chain_id="0x1") as client,
        pytest.raises(ForkRpcBindingError, match="chain ID"),
    ):
        observe_pinned_fork_rpc(
            "http://127.0.0.1:8545",
            expected_chain_id=31_337,
            pinned_block_number=42,
            client=client,
        )


def test_observe_pinned_fork_rpc_classifies_transport_failure_without_endpoint() -> None:
    def fail(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("synthetic transport failure")

    with (
        httpx.Client(transport=httpx.MockTransport(fail), trust_env=False) as client,
        pytest.raises(ForkRpcUnavailableError) as captured,
    ):
        observe_pinned_fork_rpc(
            "http://127.0.0.1:8545",
            expected_chain_id=31_337,
            pinned_block_number=42,
            client=client,
        )

    assert "127.0.0.1" not in str(captured.value)
