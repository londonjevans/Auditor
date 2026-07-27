from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from mmaudit.snapshots.importer import (
    AllowedRpcMethod,
    ImportBalanceSpec,
    ImportConfigurationSpec,
    ImportContractSpec,
    ImportOracleSpec,
    ImportProxySpec,
    ImportRoleSpec,
    ImportTimelockSpec,
    ReadOnlySnapshotImporter,
    SnapshotImportPlan,
    SnapshotImportPlanPayload,
    load_snapshot_import_plan,
    seal_snapshot_import_plan,
)
from mmaudit.snapshots.schema import ConfigurationValueKind, ProxyKind

ADDRESS_1 = "0x1111111111111111111111111111111111111111"
ADDRESS_2 = "0x2222222222222222222222222222222222222222"
ADDRESS_3 = "0x3333333333333333333333333333333333333333"
ADDRESS_4 = "0x4444444444444444444444444444444444444444"
ADDRESS_5 = "0x5555555555555555555555555555555555555555"
ADDRESS_6 = "0x6666666666666666666666666666666666666666"
ACTOR_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ACTOR_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ACTOR_C = "0xcccccccccccccccccccccccccccccccccccccccc"
BLOCK_HASH = "0x" + ("ab" * 32)
SLOT_1 = "0x" + ("0" * 63) + "1"
SLOT_2 = "0x" + ("0" * 63) + "2"
SLOT_3 = "0x" + ("0" * 63) + "3"


def _word(value: int) -> str:
    return f"{value:064x}"


def _address_storage(address: str) -> str:
    return "0x" + ("0" * 24) + address[2:]


def _plan() -> SnapshotImportPlan:
    payload = SnapshotImportPlanPayload(
        schema_version="1.0",
        snapshot_id="mocked-read-only-import",
        acknowledge_read_only=True,
        expected_chain_id=31337,
        block_number=123456,
        expected_block_hash=BLOCK_HASH,
        contracts=[
            ImportContractSpec(
                address=address,
                label=f"SyntheticContract{index}",
                source_binding=None,
            )
            for index, address in enumerate(
                [ADDRESS_1, ADDRESS_2, ADDRESS_3, ADDRESS_4, ADDRESS_5, ADDRESS_6],
                start=1,
            )
        ],
        proxies=[
            ImportProxySpec(
                proxy_address=ADDRESS_1,
                kind=ProxyKind.TRANSPARENT,
                implementation_slot=SLOT_1,
                admin_slot=SLOT_2,
                beacon_slot=None,
            )
        ],
        roles=[
            ImportRoleSpec(
                contract_address=ADDRESS_2,
                role_id="0x" + ("11" * 32),
                role_label="UPGRADER_ROLE",
                admin_role_id="0x" + ("00" * 32),
                candidate_members=[ACTOR_A],
            )
        ],
        timelocks=[
            ImportTimelockSpec(
                contract_address=ADDRESS_3,
                proposer_role_id="0x" + ("22" * 32),
                executor_role_id="0x" + ("33" * 32),
                canceller_role_id="0x" + ("44" * 32),
                proposer_candidates=[ACTOR_A],
                executor_candidates=[ACTOR_B],
                canceller_candidates=[ACTOR_C],
            )
        ],
        oracles=[
            ImportOracleSpec(
                consumer_address=ADDRESS_2,
                feed_address=ADDRESS_4,
                heartbeat_seconds=3600,
                sequencer_feed_address=ADDRESS_5,
                sequencer_grace_period_seconds=3600,
            )
        ],
        balances=[
            ImportBalanceSpec(
                account_address=ACTOR_A,
                asset_address=None,
                decimals=18,
                symbol="ETH",
            ),
            ImportBalanceSpec(
                account_address=ADDRESS_2,
                asset_address=ADDRESS_6,
                decimals=6,
                symbol="TEST",
            ),
        ],
        configuration=[
            ImportConfigurationSpec(
                contract_address=ADDRESS_2,
                key="fee_bps",
                kind=ConfigurationValueKind.UINT,
                storage_slot=SLOT_3,
            )
        ],
    )
    return seal_snapshot_import_plan(payload)


def _mock_handler(
    observed_methods: list[str],
) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method = body["method"]
        params = body["params"]
        observed_methods.append(method)
        if method == "eth_chainId":
            result: object = "0x7a69"
        elif method == "eth_getBlockByNumber":
            result = {
                "number": "0x1e240",
                "hash": BLOCK_HASH,
                "timestamp": hex(1_700_000_000),
            }
        elif method == "eth_getCode":
            result = "0x6000"
        elif method == "eth_getStorageAt":
            slot = params[1]
            result = {
                SLOT_1: _address_storage(ADDRESS_2),
                SLOT_2: _address_storage(ACTOR_A),
                SLOT_3: "0x" + _word(25),
            }[slot]
        elif method == "eth_getBalance":
            result = hex(10**18)
        elif method == "eth_call":
            data = params[0]["data"]
            selector = data[2:10]
            if selector == "91d14854":
                result = "0x" + _word(1)
            elif selector == "f27a0c92":
                result = "0x" + _word(172800)
            elif selector == "313ce567":
                result = "0x" + _word(8)
            elif selector == "feaf968c":
                result = "0x" + "".join(
                    _word(value) for value in (1, 200_000_000_000, 0, 1_699_999_900, 1)
                )
            elif selector == "70a08231":
                result = "0x" + _word(5_000_000)
            else:
                raise AssertionError(f"unexpected fixed selector: {selector}")
        else:
            raise AssertionError(f"unexpected RPC method: {method}")
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": body["id"], "result": result},
        )

    return handler


def test_mocked_import_uses_only_allowlisted_reads_and_is_deterministic() -> None:
    observed: list[str] = []
    client = httpx.Client(transport=httpx.MockTransport(_mock_handler(observed)))
    first_importer = ReadOnlySnapshotImporter(
        "http://127.0.0.1:8545",
        http_client=client,
    )
    second_importer = ReadOnlySnapshotImporter(
        "http://127.0.0.1:8545",
        http_client=client,
    )

    first = first_importer.import_snapshot(_plan(), explicitly_enabled=True)
    second = second_importer.import_snapshot(_plan(), explicitly_enabled=True)

    assert first == second
    assert first.capture_source.value == "read_only_import"
    assert first.chain.block_hash == BLOCK_HASH
    assert first.proxies[0].implementation_address == ADDRESS_2
    assert first.roles[0].members == [ACTOR_A]
    assert first.timelocks[0].minimum_delay_seconds == 172800
    assert first.oracles[0].observed_answer == 200_000_000_000
    assert first.balances[0].amount == 10**18
    assert first.balances[1].amount == 5_000_000
    assert first.configuration[0].value == "25"
    assert set(observed) <= {method.value for method in AllowedRpcMethod}
    assert not any("send" in method.lower() or "sign" in method.lower() for method in observed)
    assert "127.0.0.1" not in first.model_dump_json()
    client.close()


def test_import_requires_double_opt_in_before_any_rpc_call() -> None:
    observed: list[str] = []
    client = httpx.Client(transport=httpx.MockTransport(_mock_handler(observed)))
    importer = ReadOnlySnapshotImporter("http://127.0.0.1:8545", http_client=client)

    with pytest.raises(ValueError, match="explicit operator opt-in"):
        importer.import_snapshot(_plan(), explicitly_enabled=False)

    assert observed == []
    client.close()


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:8545",
        "http://example.invalid:8545",
        "http://user:password@127.0.0.1:8545",
        "http://127.0.0.1:8545?token=synthetic",
        "http://127.0.0.1",
    ],
)
def test_importer_rejects_non_loopback_or_credential_bearing_endpoint(
    endpoint: str,
) -> None:
    with pytest.raises(ValueError, match="loopback"):
        ReadOnlySnapshotImporter(endpoint)


def test_import_plan_round_trip_and_tamper_detection(tmp_path: Path) -> None:
    plan = _plan()
    path = tmp_path / "snapshot-import-plan.json"
    path.write_text(plan.model_dump_json(), encoding="utf-8")

    assert load_snapshot_import_plan(path) == plan
    payload = plan.model_dump(mode="json")
    payload["block_number"] += 1
    with pytest.raises(ValidationError, match="plan hash"):
        SnapshotImportPlan.model_validate(payload)
    payload = plan.model_dump(mode="json")
    payload["acknowledge_read_only"] = 1
    with pytest.raises(ValidationError, match="explicit read-only"):
        SnapshotImportPlan.model_validate(payload)


def test_plan_schema_cannot_represent_rpc_method_url_or_secret_configuration() -> None:
    assert "method" not in SnapshotImportPlan.model_fields
    assert "rpc_url" not in SnapshotImportPlan.model_fields
    assert "private_key" not in SnapshotImportPlan.model_fields
    with pytest.raises(ValidationError, match="secret-bearing"):
        ImportConfigurationSpec(
            contract_address=ADDRESS_2,
            key="privateKey",
            kind=ConfigurationValueKind.BYTES32,
            storage_slot=SLOT_3,
        )
