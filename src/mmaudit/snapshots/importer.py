"""Explicit-opt-in, allowlisted read-only importer for offline snapshots."""

from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import httpx
from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.repository.secrets import is_sensitive_workspace_name
from mmaudit.snapshots.schema import (
    ConfigurationValueKind,
    DeploymentSnapshot,
    DeploymentSnapshotPayload,
    ProxyKind,
    SnapshotBalance,
    SnapshotCaptureSource,
    SnapshotChain,
    SnapshotConfiguration,
    SnapshotContract,
    SnapshotOracle,
    SnapshotProxy,
    SnapshotRoleAssignment,
    SnapshotSourceBinding,
    SnapshotTimelock,
    seal_deployment_snapshot,
)

_ADDRESS_PATTERN = r"^0x[0-9a-f]{40}$"
_BYTES32_PATTERN = r"^0x[0-9a-f]{64}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_PLAN_BYTES = 5_000_000
_MAX_RPC_RESPONSE_BYTES = 10_000_000
_MAX_RPC_CALLS = 100_000
_HAS_ROLE_SELECTOR = "91d14854"
_GET_MIN_DELAY_SELECTOR = "f27a0c92"
_DECIMALS_SELECTOR = "313ce567"
_LATEST_ROUND_DATA_SELECTOR = "feaf968c"
_BALANCE_OF_SELECTOR = "70a08231"


class AllowedRpcMethod(StrEnum):
    """The complete JSON-RPC vocabulary available to the importer."""

    CHAIN_ID = "eth_chainId"
    GET_BLOCK_BY_NUMBER = "eth_getBlockByNumber"
    GET_CODE = "eth_getCode"
    GET_STORAGE_AT = "eth_getStorageAt"
    GET_BALANCE = "eth_getBalance"
    CALL = "eth_call"


class ImportContractSpec(StrictModel):
    address: str = Field(pattern=_ADDRESS_PATTERN)
    label: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z_$][A-Za-z0-9_$.-]{0,199}$",
    )
    source_binding: SnapshotSourceBinding | None


class ImportProxySpec(StrictModel):
    proxy_address: str = Field(pattern=_ADDRESS_PATTERN)
    kind: ProxyKind
    implementation_slot: str = Field(pattern=_BYTES32_PATTERN)
    admin_slot: str | None = Field(pattern=_BYTES32_PATTERN)
    beacon_slot: str | None = Field(pattern=_BYTES32_PATTERN)

    @model_validator(mode="after")
    def storage_slots_match_proxy_kind(self) -> ImportProxySpec:
        if self.kind is ProxyKind.MINIMAL:
            raise ValueError("read-only imports do not infer minimal-proxy bytecode targets")
        if self.kind is ProxyKind.TRANSPARENT and self.admin_slot is None:
            raise ValueError("transparent proxy imports require an admin slot")
        if self.kind is ProxyKind.BEACON and self.beacon_slot is None:
            raise ValueError("beacon proxy imports require a beacon slot")
        return self


class ImportRoleSpec(StrictModel):
    contract_address: str = Field(pattern=_ADDRESS_PATTERN)
    role_id: str = Field(pattern=_BYTES32_PATTERN)
    role_label: str = Field(
        min_length=1,
        max_length=100,
        pattern=r"^[A-Z][A-Z0-9_]{0,99}$",
    )
    admin_role_id: str | None = Field(pattern=_BYTES32_PATTERN)
    candidate_members: list[str] = Field(max_length=10_000)

    @field_validator("candidate_members")
    @classmethod
    def candidates_are_sorted_addresses(cls, value: list[str]) -> list[str]:
        _require_sorted_addresses(value, "role candidates")
        return value


class ImportTimelockSpec(StrictModel):
    contract_address: str = Field(pattern=_ADDRESS_PATTERN)
    proposer_role_id: str = Field(pattern=_BYTES32_PATTERN)
    executor_role_id: str = Field(pattern=_BYTES32_PATTERN)
    canceller_role_id: str = Field(pattern=_BYTES32_PATTERN)
    proposer_candidates: list[str] = Field(min_length=1, max_length=10_000)
    executor_candidates: list[str] = Field(min_length=1, max_length=10_000)
    canceller_candidates: list[str] = Field(max_length=10_000)

    @field_validator(
        "proposer_candidates",
        "executor_candidates",
        "canceller_candidates",
    )
    @classmethod
    def candidates_are_sorted_addresses(cls, value: list[str]) -> list[str]:
        _require_sorted_addresses(value, "timelock candidates")
        return value


class ImportOracleSpec(StrictModel):
    consumer_address: str = Field(pattern=_ADDRESS_PATTERN)
    feed_address: str = Field(pattern=_ADDRESS_PATTERN)
    heartbeat_seconds: int = Field(ge=1, le=2**64 - 1)
    sequencer_feed_address: str | None = Field(pattern=_ADDRESS_PATTERN)
    sequencer_grace_period_seconds: int | None = Field(ge=0, le=2**64 - 1)

    @model_validator(mode="after")
    def sequencer_fields_are_paired(self) -> ImportOracleSpec:
        if (self.sequencer_feed_address is None) != (self.sequencer_grace_period_seconds is None):
            raise ValueError("sequencer import fields must be declared together")
        return self


class ImportBalanceSpec(StrictModel):
    account_address: str = Field(pattern=_ADDRESS_PATTERN)
    asset_address: str | None = Field(pattern=_ADDRESS_PATTERN)
    decimals: int = Field(ge=0, le=255)
    symbol: str = Field(
        min_length=1,
        max_length=32,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$",
    )


class ImportConfigurationSpec(StrictModel):
    contract_address: str = Field(pattern=_ADDRESS_PATTERN)
    key: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,199}$",
    )
    kind: ConfigurationValueKind
    storage_slot: str = Field(pattern=_BYTES32_PATTERN)

    @model_validator(mode="after")
    def configuration_key_is_safe(self) -> ImportConfigurationSpec:
        SnapshotConfiguration(
            contract_address=self.contract_address,
            key=self.key,
            kind=self.kind,
            value=_zero_value(self.kind),
            storage_slot=self.storage_slot,
        )
        return self


class SnapshotImportPlanPayload(StrictModel):
    schema_version: Literal["1.0"]
    snapshot_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    acknowledge_read_only: Literal[True]
    expected_chain_id: int = Field(ge=1, le=2**64 - 1)
    block_number: int = Field(ge=0, le=2**64 - 1)
    expected_block_hash: str = Field(pattern=_BYTES32_PATTERN)
    contracts: list[ImportContractSpec] = Field(min_length=1, max_length=10_000)
    proxies: list[ImportProxySpec] = Field(max_length=10_000)
    roles: list[ImportRoleSpec] = Field(max_length=100_000)
    timelocks: list[ImportTimelockSpec] = Field(max_length=10_000)
    oracles: list[ImportOracleSpec] = Field(max_length=10_000)
    balances: list[ImportBalanceSpec] = Field(max_length=100_000)
    configuration: list[ImportConfigurationSpec] = Field(max_length=100_000)

    @field_validator("acknowledge_read_only", mode="before")
    @classmethod
    def acknowledgement_is_strict_true(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("snapshot import requires explicit read-only acknowledgement")
        return True

    @model_validator(mode="after")
    def plan_is_sorted_bounded_and_linked(self) -> SnapshotImportPlanPayload:
        contract_addresses = [item.address for item in self.contracts]
        _require_sorted_unique(contract_addresses, "import contract addresses")
        known_contracts = set(contract_addresses)
        proxy_addresses = [item.proxy_address for item in self.proxies]
        _require_sorted_unique(proxy_addresses, "import proxy addresses")
        role_keys = [(item.contract_address, item.role_id) for item in self.roles]
        _require_sorted_unique(role_keys, "import role bindings")
        timelock_addresses = [item.contract_address for item in self.timelocks]
        _require_sorted_unique(timelock_addresses, "import timelock addresses")
        oracle_keys = [(item.consumer_address, item.feed_address) for item in self.oracles]
        _require_sorted_unique(oracle_keys, "import oracle bindings")
        balance_keys = [(item.asset_address or "", item.account_address) for item in self.balances]
        _require_sorted_unique(balance_keys, "import balance bindings")
        configuration_keys = [(item.contract_address, item.key) for item in self.configuration]
        _require_sorted_unique(configuration_keys, "import configuration bindings")
        referenced_contracts = {
            *(item.proxy_address for item in self.proxies),
            *(item.contract_address for item in self.roles),
            *(item.contract_address for item in self.timelocks),
            *(item.consumer_address for item in self.oracles),
            *(item.feed_address for item in self.oracles),
            *(
                item.sequencer_feed_address
                for item in self.oracles
                if item.sequencer_feed_address is not None
            ),
            *(item.asset_address for item in self.balances if item.asset_address is not None),
            *(item.contract_address for item in self.configuration),
        }
        if not referenced_contracts <= known_contracts:
            raise ValueError("snapshot import plan references undeclared contract code")
        return self


class SnapshotImportPlan(SnapshotImportPlanPayload):
    plan_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def plan_hash_matches_contents(self) -> SnapshotImportPlan:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"plan_sha256"}))
        if self.plan_sha256 != expected:
            raise ValueError("snapshot import plan hash is inconsistent")
        return self


def seal_snapshot_import_plan(payload: SnapshotImportPlanPayload) -> SnapshotImportPlan:
    serialized = payload.model_dump(mode="json")
    return SnapshotImportPlan.model_validate(
        {
            **serialized,
            "plan_sha256": canonical_sha256(serialized),
        }
    )


def load_snapshot_import_plan(path: Path) -> SnapshotImportPlan:
    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to read a sensitive snapshot import plan")
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("snapshot import plan must be a regular non-link file")
    if path.stat().st_size > _MAX_PLAN_BYTES:
        raise ValueError("snapshot import plan exceeds the 5 MB limit")
    return SnapshotImportPlan.model_validate_json(path.read_text(encoding="utf-8"))


class ReadOnlySnapshotImporter:
    """Execute only the importer-owned read vocabulary against one loopback node."""

    def __init__(
        self,
        endpoint: str,
        *,
        http_client: httpx.Client | None = None,
        timeout_seconds: float = 5,
    ) -> None:
        self._endpoint = _local_rpc_endpoint(endpoint)
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        )
        self._request_id = 0

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def import_snapshot(
        self,
        plan: SnapshotImportPlan,
        *,
        explicitly_enabled: bool,
    ) -> DeploymentSnapshot:
        if explicitly_enabled is not True:
            raise ValueError("snapshot import requires explicit operator opt-in")
        block_tag = hex(plan.block_number)
        observed_chain_id = _hex_quantity(
            self._rpc(AllowedRpcMethod.CHAIN_ID, []),
            "chain ID",
        )
        if observed_chain_id != plan.expected_chain_id:
            raise ValueError("snapshot import chain ID does not match the plan")
        block = self._rpc(
            AllowedRpcMethod.GET_BLOCK_BY_NUMBER,
            [block_tag, False],
        )
        if not isinstance(block, dict):
            raise ValueError("snapshot import block response is malformed")
        block_number = _hex_quantity(block.get("number"), "block number")
        block_hash = _data_hex(block.get("hash"), 32, "block hash")
        block_timestamp = _hex_quantity(block.get("timestamp"), "block timestamp")
        if block_number != plan.block_number or block_hash != plan.expected_block_hash:
            raise ValueError("snapshot import block identity does not match the plan")

        contracts = [self._contract(contract, block_tag) for contract in plan.contracts]
        proxies = [self._proxy(proxy, block_tag) for proxy in plan.proxies]
        roles = [self._role(role, block_tag) for role in plan.roles]
        timelocks = [self._timelock(timelock, block_tag) for timelock in plan.timelocks]
        oracles = [self._oracle(oracle, block_tag) for oracle in plan.oracles]
        balances = [self._balance(balance, block_tag) for balance in plan.balances]
        configuration = [self._configuration(item, block_tag) for item in plan.configuration]
        return seal_deployment_snapshot(
            DeploymentSnapshotPayload(
                schema_version="1.0",
                format="mmaudit-offline-deployment",
                snapshot_id=plan.snapshot_id,
                capture_source=SnapshotCaptureSource.READ_ONLY_IMPORT,
                contains_source_code=False,
                contains_secrets=False,
                chain=SnapshotChain(
                    chain_id=observed_chain_id,
                    block_number=block_number,
                    block_hash=block_hash,
                    block_timestamp=block_timestamp,
                    network_label=f"chain-{observed_chain_id}",
                ),
                contracts=contracts,
                proxies=proxies,
                roles=roles,
                timelocks=timelocks,
                oracles=oracles,
                balances=balances,
                configuration=configuration,
            )
        )

    def _contract(self, specification: ImportContractSpec, block_tag: str) -> SnapshotContract:
        code = _variable_data_hex(
            self._rpc(
                AllowedRpcMethod.GET_CODE,
                [specification.address, block_tag],
            ),
            "runtime bytecode",
        )
        if code == "0x":
            raise ValueError("snapshot import contract has no runtime bytecode")
        return SnapshotContract(
            address=specification.address,
            label=specification.label,
            runtime_bytecode=code,
            runtime_bytecode_sha256=_bytecode_sha256(code),
            source_binding=specification.source_binding,
        )

    def _proxy(self, specification: ImportProxySpec, block_tag: str) -> SnapshotProxy:
        implementation = self._storage_address(
            specification.proxy_address,
            specification.implementation_slot,
            block_tag,
        )
        admin = (
            self._storage_address(
                specification.proxy_address,
                specification.admin_slot,
                block_tag,
            )
            if specification.admin_slot is not None
            else None
        )
        beacon = (
            self._storage_address(
                specification.proxy_address,
                specification.beacon_slot,
                block_tag,
            )
            if specification.beacon_slot is not None
            else None
        )
        return SnapshotProxy(
            proxy_address=specification.proxy_address,
            kind=specification.kind,
            implementation_address=implementation,
            admin_address=admin,
            beacon_address=beacon,
            implementation_slot=specification.implementation_slot,
            admin_slot=specification.admin_slot,
            beacon_slot=specification.beacon_slot,
        )

    def _role(self, specification: ImportRoleSpec, block_tag: str) -> SnapshotRoleAssignment:
        members = [
            member
            for member in specification.candidate_members
            if self._has_role(
                specification.contract_address,
                specification.role_id,
                member,
                block_tag,
            )
        ]
        return SnapshotRoleAssignment(
            contract_address=specification.contract_address,
            role_id=specification.role_id,
            role_label=specification.role_label,
            admin_role_id=specification.admin_role_id,
            members=members,
        )

    def _timelock(
        self,
        specification: ImportTimelockSpec,
        block_tag: str,
    ) -> SnapshotTimelock:
        delay = _abi_uint(
            self._eth_call(
                specification.contract_address,
                "0x" + _GET_MIN_DELAY_SELECTOR,
                block_tag,
            ),
            "timelock delay",
        )
        proposers = self._role_members(
            specification.contract_address,
            specification.proposer_role_id,
            specification.proposer_candidates,
            block_tag,
        )
        executors = self._role_members(
            specification.contract_address,
            specification.executor_role_id,
            specification.executor_candidates,
            block_tag,
        )
        cancellers = self._role_members(
            specification.contract_address,
            specification.canceller_role_id,
            specification.canceller_candidates,
            block_tag,
        )
        return SnapshotTimelock(
            contract_address=specification.contract_address,
            minimum_delay_seconds=delay,
            proposers=proposers,
            executors=executors,
            cancellers=cancellers,
        )

    def _oracle(self, specification: ImportOracleSpec, block_tag: str) -> SnapshotOracle:
        decimals = _abi_uint(
            self._eth_call(
                specification.feed_address,
                "0x" + _DECIMALS_SELECTOR,
                block_tag,
            ),
            "oracle decimals",
        )
        if decimals > 255:
            raise ValueError("snapshot import oracle decimals exceed uint8")
        round_data = _abi_words(
            self._eth_call(
                specification.feed_address,
                "0x" + _LATEST_ROUND_DATA_SELECTOR,
                block_tag,
            ),
            expected_words=5,
            label="oracle round data",
        )
        answer = _signed_word(round_data[1])
        updated_at = int.from_bytes(round_data[3], "big")
        return SnapshotOracle(
            consumer_address=specification.consumer_address,
            feed_address=specification.feed_address,
            feed_decimals=decimals,
            heartbeat_seconds=specification.heartbeat_seconds,
            observed_answer=answer,
            updated_at=updated_at,
            sequencer_feed_address=specification.sequencer_feed_address,
            sequencer_grace_period_seconds=(specification.sequencer_grace_period_seconds),
        )

    def _balance(self, specification: ImportBalanceSpec, block_tag: str) -> SnapshotBalance:
        if specification.asset_address is None:
            amount = _hex_quantity(
                self._rpc(
                    AllowedRpcMethod.GET_BALANCE,
                    [specification.account_address, block_tag],
                ),
                "native balance",
            )
        else:
            amount = _abi_uint(
                self._eth_call(
                    specification.asset_address,
                    "0x" + _BALANCE_OF_SELECTOR + _address_word(specification.account_address),
                    block_tag,
                ),
                "token balance",
            )
        return SnapshotBalance(
            account_address=specification.account_address,
            asset_address=specification.asset_address,
            amount=amount,
            decimals=specification.decimals,
            symbol=specification.symbol,
        )

    def _configuration(
        self,
        specification: ImportConfigurationSpec,
        block_tag: str,
    ) -> SnapshotConfiguration:
        word = _data_hex(
            self._rpc(
                AllowedRpcMethod.GET_STORAGE_AT,
                [
                    specification.contract_address,
                    specification.storage_slot,
                    block_tag,
                ],
            ),
            32,
            "configuration storage",
        )
        return SnapshotConfiguration(
            contract_address=specification.contract_address,
            key=specification.key,
            kind=specification.kind,
            value=_configuration_value(specification.kind, word),
            storage_slot=specification.storage_slot,
        )

    def _storage_address(self, address: str, slot: str, block_tag: str) -> str:
        word = _data_hex(
            self._rpc(
                AllowedRpcMethod.GET_STORAGE_AT,
                [address, slot, block_tag],
            ),
            32,
            "proxy storage",
        )
        if int(word, 16) >> 160:
            raise ValueError("snapshot import address slot contains non-address high bits")
        observed = "0x" + word[-40:]
        if observed == "0x" + ("0" * 40):
            raise ValueError("snapshot import address slot is zero")
        return observed

    def _role_members(
        self,
        contract_address: str,
        role_id: str,
        candidates: list[str],
        block_tag: str,
    ) -> list[str]:
        return [
            candidate
            for candidate in candidates
            if self._has_role(contract_address, role_id, candidate, block_tag)
        ]

    def _has_role(
        self,
        contract_address: str,
        role_id: str,
        member: str,
        block_tag: str,
    ) -> bool:
        value = _abi_uint(
            self._eth_call(
                contract_address,
                "0x" + _HAS_ROLE_SELECTOR + role_id[2:] + _address_word(member),
                block_tag,
            ),
            "role membership",
        )
        if value not in {0, 1}:
            raise ValueError("snapshot import role response is not boolean")
        return value == 1

    def _eth_call(self, address: str, data: str, block_tag: str) -> str:
        return _variable_data_hex(
            self._rpc(
                AllowedRpcMethod.CALL,
                [{"to": address, "data": data}, block_tag],
            ),
            "contract read",
        )

    def _rpc(self, method: AllowedRpcMethod, params: list[object]) -> object:
        self._request_id += 1
        if self._request_id > _MAX_RPC_CALLS:
            raise ValueError("snapshot import RPC call limit exceeded")
        try:
            response = self._client.post(
                self._endpoint,
                json={
                    "jsonrpc": "2.0",
                    "id": self._request_id,
                    "method": method.value,
                    "params": params,
                },
            )
            content = response.content
        except httpx.HTTPError as exc:
            raise ValueError(f"snapshot read failed for {method.value}") from exc
        if response.status_code != 200 or len(content) > _MAX_RPC_RESPONSE_BYTES:
            raise ValueError(f"snapshot read failed for {method.value}")
        try:
            payload = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ValueError(f"snapshot read returned invalid JSON for {method.value}") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("jsonrpc") != "2.0"
            or payload.get("id") != self._request_id
            or "error" in payload
            or "result" not in payload
        ):
            raise ValueError(f"snapshot read returned an error for {method.value}")
        return payload["result"]


def _local_rpc_endpoint(value: str) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.port is None
        or parsed.path not in {"", "/"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("snapshot imports require a plain HTTP loopback RPC endpoint")
    return value


def _hex_quantity(value: object, label: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]*)", value) is None:
        raise ValueError(f"snapshot import {label} is not a canonical hex quantity")
    return int(value, 16)


def _data_hex(value: object, length: int, label: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            rf"0x[0-9a-f]{{{length * 2}}}",
            value,
        )
        is None
    ):
        raise ValueError(f"snapshot import {label} is not {length} bytes")
    return value


def _variable_data_hex(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 2 + 24_576 * 2
        or re.fullmatch(r"0x(?:[0-9a-f]{2})*", value) is None
    ):
        raise ValueError(f"snapshot import {label} is not bounded canonical bytes")
    return value


def _abi_words(value: str, *, expected_words: int, label: str) -> list[bytes]:
    raw = bytes.fromhex(value[2:])
    if len(raw) != expected_words * 32:
        raise ValueError(f"snapshot import {label} has an unexpected ABI length")
    return [raw[index : index + 32] for index in range(0, len(raw), 32)]


def _abi_uint(value: str, label: str) -> int:
    return int.from_bytes(_abi_words(value, expected_words=1, label=label)[0], "big")


def _signed_word(value: bytes) -> int:
    unsigned = int.from_bytes(value, "big")
    return unsigned - 2**256 if unsigned >= 2**255 else unsigned


def _address_word(value: str) -> str:
    return ("0" * 24) + value[2:]


def _bytecode_sha256(value: str) -> str:
    return hashlib.sha256(bytes.fromhex(value[2:])).hexdigest()


def _configuration_value(kind: ConfigurationValueKind, word: str) -> str:
    raw = bytes.fromhex(word[2:])
    unsigned = int.from_bytes(raw, "big")
    if kind is ConfigurationValueKind.UINT:
        return str(unsigned)
    if kind is ConfigurationValueKind.INT:
        return str(_signed_word(raw))
    if kind is ConfigurationValueKind.BOOL:
        if unsigned not in {0, 1}:
            raise ValueError("snapshot import boolean storage is not canonical")
        return "true" if unsigned else "false"
    if kind is ConfigurationValueKind.ADDRESS:
        if unsigned >> 160:
            raise ValueError("snapshot import address storage contains high bits")
        return "0x" + word[-40:]
    return word


def _zero_value(kind: ConfigurationValueKind) -> str:
    if kind in {ConfigurationValueKind.UINT, ConfigurationValueKind.INT}:
        return "0"
    if kind is ConfigurationValueKind.BOOL:
        return "false"
    if kind is ConfigurationValueKind.ADDRESS:
        return "0x" + ("0" * 40)
    return "0x" + ("0" * 64)


def _require_sorted_addresses(values: list[str], label: str) -> None:
    if values != sorted(set(values)) or any(
        re.fullmatch(_ADDRESS_PATTERN, value) is None for value in values
    ):
        raise ValueError(f"{label} must be lowercase, unique, and sorted")


def _require_sorted_unique[SortableT: (str, tuple[str, str])](
    values: list[SortableT],
    label: str,
) -> None:
    if values != sorted(set(values)):
        raise ValueError(f"{label} must be unique and sorted")
