"""Real in-process HTTP client/identity parser over frozen reads, never a live fork or socket."""

from __future__ import annotations

import hashlib
import shutil
import socket
import subprocess

import httpx
import pytest

from mmaudit.scanners.fork_rpc import observe_pinned_fork_rpc
from mmaudit.scanners.offline_fork_rpc import OfflineForkRpcError, load_offline_fork_rpc_archive
from tests.unit.test_offline_fork_rpc import ADDRESS, BLOCK_HASH, FIXTURE, _request


@pytest.mark.parametrize("repeat", [False, True])
def test_real_identity_parser_consumes_frozen_offline_reads_without_network(
    tmp_path, monkeypatch, repeat
):
    root = tmp_path.resolve(strict=True)
    source = root / "reads.json"
    shutil.copyfile(FIXTURE, source)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: archived read replay cannot contact a chain or execute tools")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    replay = load_offline_fork_rpc_archive(
        root,
        source.name,
        expected_sha256=digest,
        expected_chain_id=31337,
        pinned_block_number=7,
    )
    calls = []

    def in_process(request):
        calls.append(request.content)
        return httpx.Response(200, content=replay.respond(request.content))

    # Only transport is in-process; exercise the ordinary HTTP client and the
    # production identity parser. No server, engine or backend seal is created.
    with httpx.Client(transport=httpx.MockTransport(in_process), trust_env=False) as client:
        for _ in range(2 if repeat else 1):
            observed = observe_pinned_fork_rpc(
                "http://127.0.0.1:18545",
                expected_chain_id=31337,
                pinned_block_number=7,
                client=client,
            )
            assert observed == replay.observation
            assert observed.block_hash == BLOCK_HASH
        response = client.post(
            "http://127.0.0.1:18545", content=_request("eth_getBalance", [ADDRESS, "0x7"])
        )
        assert response.json()["result"] == "0x5"
        with pytest.raises(OfflineForkRpcError):
            client.post("http://127.0.0.1:18545", content=_request("eth_getCode", [ADDRESS, "0x7"]))
    assert len(calls) == (6 if repeat else 4)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
    replay.verify_source()
    assert replay.complete_state is replay.runtime_authority is False
    assert list(root.iterdir()) == [source]
