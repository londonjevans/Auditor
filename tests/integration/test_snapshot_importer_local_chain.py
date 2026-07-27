from __future__ import annotations

import shutil
import socket
import subprocess
import time
from typing import Any

import httpx
import pytest

from mmaudit.snapshots.importer import (
    ImportContractSpec,
    ReadOnlySnapshotImporter,
    SnapshotImportPlanPayload,
    seal_snapshot_import_plan,
)

CONTRACT = "0x1111111111111111111111111111111111111111"


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _rpc(client: httpx.Client, endpoint: str, method: str, params: list[object]) -> Any:
    response = client.post(
        endpoint,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
    )
    response.raise_for_status()
    payload = response.json()
    assert "error" not in payload
    return payload["result"]


def test_read_only_snapshot_importer_against_disposable_local_anvil() -> None:
    anvil = shutil.which("anvil")
    if anvil is None:
        pytest.skip("anvil is not installed")
    try:
        port = _free_loopback_port()
    except PermissionError:
        pytest.skip("loopback binding is unavailable in the current sandbox")
    endpoint = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [
            anvil,
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--chain-id",
            "31337",
            "--accounts",
            "0",
            "--quiet",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=False,
    )
    client = httpx.Client(timeout=1, follow_redirects=False, trust_env=False)
    importer: ReadOnlySnapshotImporter | None = None
    try:
        for _ in range(60):
            try:
                _rpc(client, endpoint, "eth_chainId", [])
                break
            except (httpx.HTTPError, KeyError, ValueError):
                time.sleep(0.05)
        else:
            raise AssertionError("disposable local anvil did not become ready")
        assert _rpc(client, endpoint, "anvil_setCode", [CONTRACT, "0x6000"]) is None
        _rpc(client, endpoint, "evm_mine", [])
        block = _rpc(client, endpoint, "eth_getBlockByNumber", ["latest", False])
        block_number = int(block["number"], 16)
        plan = seal_snapshot_import_plan(
            SnapshotImportPlanPayload(
                schema_version="1.0",
                snapshot_id="local-anvil-read-only",
                acknowledge_read_only=True,
                expected_chain_id=31337,
                block_number=block_number,
                expected_block_hash=block["hash"],
                contracts=[
                    ImportContractSpec(
                        address=CONTRACT,
                        label="SyntheticLocalContract",
                        source_binding=None,
                    )
                ],
                proxies=[],
                roles=[],
                timelocks=[],
                oracles=[],
                balances=[],
                configuration=[],
            )
        )
        importer = ReadOnlySnapshotImporter(endpoint)

        snapshot = importer.import_snapshot(plan, explicitly_enabled=True)

        assert snapshot.chain.chain_id == 31337
        assert snapshot.chain.block_number == block_number
        assert snapshot.contracts[0].runtime_bytecode == "0x6000"
        assert endpoint not in snapshot.model_dump_json()
    finally:
        if importer is not None:
            importer.close()
        client.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
