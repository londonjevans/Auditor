from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.snapshots.schema import (
    DeploymentSnapshot,
    DeploymentSnapshotPayload,
    SnapshotBalance,
    SnapshotChain,
    SnapshotCompilerBinding,
    SnapshotConfiguration,
    SnapshotContract,
    SnapshotImmutableBinding,
    SnapshotLibraryBinding,
    SnapshotOracle,
    SnapshotProxy,
    SnapshotRoleAssignment,
    SnapshotSourceBinding,
    SnapshotTimelock,
    load_deployment_snapshot,
    seal_deployment_snapshot,
    write_deployment_snapshot,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "snapshots"


def test_valid_offline_snapshot_is_complete_hash_linked_and_stable(
    tmp_path: Path,
) -> None:
    snapshot = load_deployment_snapshot(FIXTURES / "valid.json")
    payload = DeploymentSnapshotPayload.model_validate(
        snapshot.model_dump(mode="json", exclude={"snapshot_sha256"})
    )
    resealed = seal_deployment_snapshot(payload)

    assert resealed == snapshot
    assert snapshot.contains_source_code is False
    assert snapshot.contains_secrets is False
    assert snapshot.chain.chain_id == 31337
    assert snapshot.chain.block_number == 123456
    assert len(snapshot.contracts) == 6
    assert snapshot.proxies and snapshot.roles and snapshot.timelocks
    assert snapshot.oracles and snapshot.balances and snapshot.configuration
    assert snapshot.contracts[1].source_binding is not None
    serialized = snapshot.model_dump(mode="json")
    assert "source_code" not in serialized["contracts"][1]["source_binding"]
    assert "rpc_url" not in json.dumps(serialized)

    output = tmp_path / "snapshot.json"
    write_deployment_snapshot(output, snapshot)
    assert load_deployment_snapshot(output) == snapshot


def test_snapshot_rejects_malformed_bytecode_and_canonical_hash_tampering() -> None:
    with pytest.raises(ValidationError, match="runtime bytecode hash"):
        load_deployment_snapshot(FIXTURES / "malformed.json")

    payload = json.loads((FIXTURES / "valid.json").read_text(encoding="utf-8"))
    payload["chain"]["block_number"] += 1
    with pytest.raises(ValidationError, match="self-hash"):
        DeploymentSnapshot.model_validate(payload)


def test_snapshot_rejects_traversal_and_unbound_observations() -> None:
    with pytest.raises(ValidationError):
        load_deployment_snapshot(FIXTURES / "traversal.json")

    payload = json.loads((FIXTURES / "valid.json").read_text(encoding="utf-8"))
    payload["oracles"][0]["feed_address"] = "0x7777777777777777777777777777777777777777"
    with pytest.raises(ValidationError, match="unbound deployed code"):
        DeploymentSnapshot.model_validate(payload)


def test_snapshot_withholds_secret_bearing_fields_and_filenames(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="secret-bearing"):
        load_deployment_snapshot(FIXTURES / "secret-bearing.json")

    payload = json.loads((FIXTURES / "valid.json").read_text(encoding="utf-8"))
    payload["contracts"][1]["source_binding"]["source_code"] = "synthetic prohibited content"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        DeploymentSnapshot.model_validate(payload)

    sensitive_name = tmp_path / "wallet.json"
    sensitive_name.write_text(
        (FIXTURES / "valid.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="sensitive snapshot filename"):
        load_deployment_snapshot(sensitive_name)

    payload = json.loads((FIXTURES / "valid.json").read_text(encoding="utf-8"))
    payload.pop("snapshot_sha256")
    payload["contains_secrets"] = 0
    with pytest.raises(ValidationError, match="cannot declare source code or secrets"):
        DeploymentSnapshotPayload.model_validate(payload)


def test_snapshot_loader_and_writer_refuse_links(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text(
        (FIXTURES / "valid.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    linked = tmp_path / "linked.json"
    try:
        linked.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")

    with pytest.raises(ValueError, match="regular non-link"):
        load_deployment_snapshot(linked)
    snapshot = load_deployment_snapshot(FIXTURES / "valid.json")
    with pytest.raises(ValueError, match="destination may not be a link"):
        write_deployment_snapshot(linked, snapshot)


def test_snapshot_rejects_ordering_duplicates_and_future_oracle_state() -> None:
    payload = json.loads((FIXTURES / "valid.json").read_text(encoding="utf-8"))
    payload["contracts"].reverse()
    with pytest.raises(ValidationError, match="contract addresses must be unique and sorted"):
        DeploymentSnapshot.model_validate(payload)

    payload = json.loads((FIXTURES / "valid.json").read_text(encoding="utf-8"))
    payload["configuration"].append(payload["configuration"][-1])
    with pytest.raises(ValidationError, match="configuration bindings"):
        DeploymentSnapshot.model_validate(payload)

    payload = json.loads((FIXTURES / "valid.json").read_text(encoding="utf-8"))
    payload["oracles"][0]["updated_at"] = payload["chain"]["block_timestamp"] + 1
    with pytest.raises(ValidationError, match="pinned block timestamp"):
        DeploymentSnapshot.model_validate(payload)


def test_published_snapshot_schema_is_strict_bounded_and_complete() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "deployment_snapshot.schema.json").read_text(encoding="utf-8")
    )

    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(DeploymentSnapshot.model_fields)
    assert schema["properties"]["contracts"]["maxItems"] == 10_000
    assert schema["properties"]["configuration"]["maxItems"] == 100_000
    assert schema["properties"]["contains_source_code"]["const"] is False
    assert schema["properties"]["contains_secrets"]["const"] is False
    for definition in (
        "balance",
        "chain",
        "compilerBinding",
        "configuration",
        "contract",
        "immutableBinding",
        "libraryBinding",
        "oracle",
        "proxy",
        "role",
        "sourceBinding",
        "timelock",
    ):
        assert schema["$defs"][definition]["additionalProperties"] is False
    models = {
        "balance": SnapshotBalance,
        "chain": SnapshotChain,
        "compilerBinding": SnapshotCompilerBinding,
        "configuration": SnapshotConfiguration,
        "contract": SnapshotContract,
        "immutableBinding": SnapshotImmutableBinding,
        "libraryBinding": SnapshotLibraryBinding,
        "oracle": SnapshotOracle,
        "proxy": SnapshotProxy,
        "role": SnapshotRoleAssignment,
        "sourceBinding": SnapshotSourceBinding,
        "timelock": SnapshotTimelock,
    }
    for definition, model in models.items():
        assert set(schema["$defs"][definition]["required"]) == set(model.model_fields)
