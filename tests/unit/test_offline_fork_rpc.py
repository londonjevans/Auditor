"""Bounded synthetic offline reads cannot imply complete chain state or execution authority."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from mmaudit.scanners import offline_fork_rpc
from mmaudit.scanners.offline_fork_rpc import OfflineForkRpcError, load_offline_fork_rpc_archive

FIXTURE = Path(__file__).parents[1] / "fixtures/offline_fork_rpc/reads.json"
ADDRESS = "0x" + "1" * 40
BLOCK_HASH = "0x" + "b" * 64


@pytest.fixture(autouse=True)
def forbid_external_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: offline fork reads cannot execute, connect or discover tools")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)


@pytest.fixture
def source(tmp_path):
    root = tmp_path.resolve(strict=True)
    path = root / "reads.json"
    shutil.copyfile(FIXTURE, path)
    return root, path


def _load(source, **kwargs):
    root, path = source
    return load_offline_fork_rpc_archive(
        root,
        kwargs.pop("relative_path", path.name),
        expected_sha256=kwargs.pop(
            "expected_sha256", hashlib.sha256(path.read_bytes()).hexdigest()
        ),
        expected_chain_id=kwargs.pop("expected_chain_id", 31337),
        pinned_block_number=kwargs.pop("pinned_block_number", 7),
        **kwargs,
    )


def _request(method, params, request_id=1):
    return json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    ).encode()


def test_pinned_read_replay_matches_identity_and_exact_data_without_network(source):
    replay = _load(source)
    assert replay.observation.chain_id == 31337
    assert replay.observation.block_number == 7
    assert replay.observation.block_hash == BLOCK_HASH
    assert replay.runtime_authority is replay.complete_state is False
    assert replay.source_binding.sha256 == hashlib.sha256(source[1].read_bytes()).hexdigest()
    assert json.loads(replay.respond(_request("eth_chainId", [])))["result"] == "0x7a69"
    block = json.loads(replay.respond(_request("eth_getBlockByNumber", ["0x7", False])))
    assert block["result"] == {"number": "0x7", "hash": BLOCK_HASH}
    result = json.loads(replay.respond(_request("eth_getBalance", [ADDRESS, "latest"], "safe-id")))
    assert result == {"jsonrpc": "2.0", "id": "safe-id", "result": "0x5"}


@pytest.mark.parametrize(
    "field,value",
    [
        ("expected_sha256", "a" * 64),
        ("expected_sha256", "0" * 64),
        ("expected_chain_id", 1),
        ("expected_chain_id", True),
        ("pinned_block_number", 8),
        ("pinned_block_number", False),
    ],
)
def test_mismatched_or_malformed_pins_refuse_before_replay(source, field, value):
    with pytest.raises(OfflineForkRpcError):
        _load(source, **{field: value})


@pytest.mark.parametrize(
    "method,params",
    [
        ("eth_getBalance", ["0x" + "2" * 40, "0x7"]),
        ("eth_getStorageAt", [ADDRESS, "0x1", "0x7"]),
        ("eth_getCode", [ADDRESS, "0x7"]),
        ("eth_getBalance", [ADDRESS, "0x8"]),
        ("eth_sendRawTransaction", ["0x00"]),
        ("anvil_setBalance", [ADDRESS, "0x10"]),
    ],
)
def test_unknown_state_and_mutation_methods_never_return_synthetic_zero(source, method, params):
    replay = _load(source)
    with pytest.raises(OfflineForkRpcError):
        replay.respond(_request(method, params))


@pytest.mark.parametrize(
    "mutation", ["duplicate", "contradiction", "wrong_block", "alias", "authority", "complete"]
)
def test_untrusted_archive_rows_cannot_change_pins_or_claim_completeness(source, mutation):
    payload = json.loads(source[1].read_text())
    if mutation in {"duplicate", "contradiction"}:
        row = payload["reads"][1].copy()
        if mutation == "contradiction":
            row["result"] = "0x6"
        payload["reads"].append(row)
    elif mutation == "wrong_block":
        payload["reads"][0]["result"]["hash"] = "0x" + "a" * 64
    elif mutation == "alias":
        payload["reads"][1]["params"][1] = "latest"
    else:
        payload["runtime_authority" if mutation == "authority" else "complete_state"] = True
    source[1].write_text(json.dumps(payload))
    with pytest.raises(OfflineForkRpcError):
        _load(source)


def test_loaded_bytes_are_detached_and_source_revalidation_detects_changes(source):
    replay = _load(source)
    original = replay.respond(_request("eth_getBalance", [ADDRESS, "0x7"]))
    source[1].write_text("{}")
    with pytest.raises(OfflineForkRpcError):
        replay.verify_source()
    assert replay.respond(_request("eth_getBalance", [ADDRESS, "0x7"])) == original


def test_mixed_batch_fails_atomically_without_partial_results(source):
    replay = _load(source)
    body = (
        b"["
        + _request("eth_chainId", [], 1)
        + b","
        + _request("eth_getCode", [ADDRESS, "0x7"], 2)
        + b"]"
    )
    with pytest.raises(OfflineForkRpcError):
        replay.respond(body)


@pytest.mark.parametrize("body", [b"{}", b"[]", b"null", b'{"id":1,"id":2}', b"\xef\xbb\xbf{}"])
def test_malformed_requests_refuse_without_echoing_input(source, body):
    with pytest.raises(OfflineForkRpcError):
        _load(source).respond(body)


@pytest.mark.parametrize("field", ["max_requests", "max_calls"])
@pytest.mark.parametrize("value", [0, -1, True, 100001, 1.5])
def test_replay_budgets_cannot_be_unbounded_or_coerced(source, field, value):
    with pytest.raises(OfflineForkRpcError):
        _load(source, **{field: value})


def test_atomic_concurrent_request_budget_is_hard_saturating(source):
    replay = _load(source, max_requests=3)

    def call(_index):
        try:
            return replay.respond(_request("eth_chainId", []))
        except OfflineForkRpcError:
            return None

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(call, range(12)))
    assert sum(result is not None for result in results) == 3
    assert call(12) is None


def test_oversize_batch_consumes_call_budget_without_partial_result(source):
    replay = _load(source, max_calls=1)
    body = b"[" + _request("eth_chainId", [], 1) + b"," + _request("eth_blockNumber", [], 2) + b"]"
    with pytest.raises(OfflineForkRpcError):
        replay.respond(body)
    with pytest.raises(OfflineForkRpcError):
        replay.respond(_request("eth_chainId", []))


@pytest.mark.parametrize("field", ["runtime_authority", "complete_state"])
@pytest.mark.parametrize("value", [True, 0, "false", None])
def test_archive_non_authority_is_literal_and_required(source, field, value):
    payload = json.loads(source[1].read_text())
    if value is None:
        del payload[field]
    else:
        payload[field] = value
    source[1].write_text(json.dumps(payload))
    with pytest.raises(OfflineForkRpcError):
        _load(source)


@pytest.mark.parametrize(
    "mutation", ["file_link", "hard_link", "root_link", "parent_link", "traversal"]
)
def test_archive_paths_reject_links_and_traversal(source, mutation):
    root, path = source
    selected_root = root
    selected_path = path.name
    if mutation == "root_link":
        selected_root = root.parent / "source-root-alias"
        selected_root.symlink_to(root, target_is_directory=True)
    elif mutation == "traversal":
        selected_path = "../" + root.name + "/reads.json"
    else:
        alias = root / "alias"
        if mutation == "file_link":
            alias.symlink_to(path)
            selected_path = alias.name
        elif mutation == "hard_link":
            alias.hardlink_to(path)
        else:
            alias.symlink_to(root, target_is_directory=True)
            selected_path = "alias/reads.json"
    with pytest.raises(OfflineForkRpcError):
        load_offline_fork_rpc_archive(
            selected_root,
            selected_path,
            expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            expected_chain_id=31337,
            pinned_block_number=7,
        )


@pytest.mark.parametrize(
    "mutation", ["duplicate_keys", "nonfinite", "overflow", "depth", "missing_block", "bad_result"]
)
def test_bad_archive_json_and_missing_identity_are_refused(source, mutation):
    if mutation == "duplicate_keys":
        content = b'{"schema_version":"1.0","schema_version":"1.0"}'
    elif mutation in {"nonfinite", "overflow"}:
        content = b'{"unexpected":' + (b"NaN" if mutation == "nonfinite" else b"1e400") + b"}"
    elif mutation == "depth":
        content = b"[" * 40 + b"0" + b"]" * 40
    else:
        payload = json.loads(source[1].read_text())
        if mutation == "missing_block":
            payload["reads"].pop(0)
        else:
            payload["reads"][1]["result"] = "0x00"
        content = json.dumps(payload).encode()
    source[1].write_bytes(content)
    with pytest.raises(OfflineForkRpcError):
        _load(source)


@pytest.mark.parametrize("balance", ["0x5", "0x6"])
def test_account_info_must_agree_with_individual_account_reads(source, balance):
    payload = json.loads(source[1].read_text())
    payload["reads"].append(
        {
            "method": "eth_getAccountInfo",
            "params": payload["reads"][1]["params"],
            "result": {"balance": balance, "nonce": "0x0", "code": "0x"},
        }
    )
    source[1].write_text(json.dumps(payload))
    if balance == "0x6":
        with pytest.raises(OfflineForkRpcError):
            _load(source)
    else:
        replay = _load(source)
        result = json.loads(replay.respond(_request("eth_getAccountInfo", [ADDRESS, "0x7"])))
        assert result["result"]["balance"] == "0x5"


def test_request_and_aggregate_response_bounds_are_enforced_incrementally(source, monkeypatch):
    replay = _load(source)
    monkeypatch.setattr(offline_fork_rpc, "_MAX_REQUEST_BYTES", 64)
    with pytest.raises(OfflineForkRpcError):
        replay.respond(b" " * 65)
    monkeypatch.setattr(offline_fork_rpc, "_MAX_REQUEST_BYTES", 1024)
    monkeypatch.setattr(offline_fork_rpc, "_MAX_RESPONSE_BYTES", 80)
    assert json.loads(replay.respond(_request("eth_chainId", [])))["result"] == "0x7a69"
    body = b"[" + _request("eth_chainId", [], 1) + b"," + _request("eth_chainId", [], 2) + b"]"
    with pytest.raises(OfflineForkRpcError):
        replay.respond(body)


def test_source_binding_is_detached_and_replay_cannot_bypass_loader(source):
    replay = _load(source)
    binding = replay.source_binding
    assert binding is not replay.source_binding
    with pytest.raises(OfflineForkRpcError, match="admission"):
        offline_fork_rpc.OfflineForkRpcReplay(
            root=source[0],
            relative_path=source[1].name,
            content=b"{}",
            binding=binding,
            archive=object(),
            max_requests=1,
            max_calls=1,
        )


def test_shared_bridge_policy_is_used_without_constructing_a_live_bridge(source, monkeypatch):
    from mmaudit.scanners.read_only_rpc import ReadOnlyRpcBridge, _PinnedRpcReadPolicy

    assert ReadOnlyRpcBridge._prepare_payload is _PinnedRpcReadPolicy._prepare_payload
    assert ReadOnlyRpcBridge._prepare_call is _PinnedRpcReadPolicy._prepare_call

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: in-process replay cannot construct an upstream bridge")

    monkeypatch.setattr(ReadOnlyRpcBridge, "__init__", forbidden)
    assert _load(source).respond(_request("eth_chainId", []))


def test_archive_file_byte_bound_precedes_parsing(source, monkeypatch):
    monkeypatch.setattr(offline_fork_rpc, "_MAX_ARCHIVE_BYTES", 64)
    with pytest.raises(OfflineForkRpcError):
        _load(source)


def test_archive_row_count_is_bounded_before_replay(source):
    payload = json.loads(source[1].read_text())
    payload["reads"] = [payload["reads"][0]] * 4097
    source[1].write_text(json.dumps(payload))
    with pytest.raises(OfflineForkRpcError):
        _load(source)


@pytest.mark.parametrize("root", [Path("."), Path("relative"), "not-a-path", None])
def test_archive_root_cannot_depend_on_ambient_working_directory_or_wrong_type(source, root):
    with pytest.raises(OfflineForkRpcError):
        load_offline_fork_rpc_archive(
            root,
            "reads.json",
            expected_sha256="a" * 64,
            expected_chain_id=31337,
            pinned_block_number=7,
        )
