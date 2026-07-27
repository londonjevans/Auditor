"""Strict, source-free offline deployment snapshot format."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import write_json
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_path

_ADDRESS_PATTERN = r"^0x[0-9a-f]{40}$"
_BYTES32_PATTERN = r"^0x[0-9a-f]{64}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_BYTECODE_PATTERN = r"^0x(?:[0-9a-f]{2})+$"
_MAX_SNAPSHOT_BYTES = 20_000_000
_MAX_RUNTIME_BYTECODE_HEX_LENGTH = 49_154
_SENSITIVE_CONFIGURATION_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"(?:^|_)api_key(?:_|$)",
        r"(?:^|_)access_token(?:_|$)",
        r"(?:^|_)auth_token(?:_|$)",
        r"(?:^|_)bearer_token(?:_|$)",
        r"(?:^|_)client_secret(?:_|$)",
        r"(?:^|_)credential(?:s)?(?:_|$)",
        r"(?:^|_)keystore(?:_|$)",
        r"(?:^|_)mnemonic(?:_|$)",
        r"(?:^|_)passphrase(?:_|$)",
        r"(?:^|_)password(?:_|$)",
        r"(?:^|_)private_key(?:_|$)",
        r"(?:^|_)rpc_url(?:_|$)",
        r"(?:^|_)secret(?:s)?(?:_|$)",
        r"(?:^|_)seed_phrase(?:_|$)",
        r"(?:^|_)signing_key(?:_|$)",
    )
)


class SnapshotCaptureSource(StrEnum):
    """Non-secret provenance for how an offline snapshot was assembled."""

    OPERATOR_SUPPLIED = "operator_supplied"
    READ_ONLY_IMPORT = "read_only_import"


class ProxyKind(StrEnum):
    """Bounded proxy forms represented without executing deployment code."""

    TRANSPARENT = "transparent"
    UUPS = "uups"
    BEACON = "beacon"
    MINIMAL = "minimal"
    UNKNOWN = "unknown"


class ConfigurationValueKind(StrEnum):
    """Canonical value vocabulary; arbitrary strings and secret blobs are excluded."""

    UINT = "uint"
    INT = "int"
    BOOL = "bool"
    ADDRESS = "address"
    BYTES32 = "bytes32"


class SnapshotChain(StrictModel):
    """Exact chain and block identity used by every observation."""

    chain_id: int = Field(ge=1, le=2**64 - 1)
    block_number: int = Field(ge=0, le=2**64 - 1)
    block_hash: str = Field(pattern=_BYTES32_PATTERN)
    block_timestamp: int = Field(ge=0, le=2**64 - 1)
    network_label: str | None = Field(
        min_length=1,
        max_length=100,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$",
    )


class SnapshotCompilerBinding(StrictModel):
    """Expected compiler projection and full-settings hash for one source binding."""

    compiler_version: str = Field(
        min_length=1,
        max_length=100,
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*$",
    )
    evm_version: str = Field(
        min_length=1,
        max_length=50,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$",
    )
    optimizer_enabled: bool
    optimizer_runs: int = Field(ge=0, le=2**32 - 1)
    via_ir: bool
    metadata_bytecode_hash: Literal["ipfs", "bzzr1", "none"]
    settings_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def optimizer_fields_are_consistent(self) -> SnapshotCompilerBinding:
        if not self.optimizer_enabled and self.optimizer_runs != 0:
            raise ValueError("disabled optimizer snapshots must record zero optimizer runs")
        return self


class SnapshotLibraryBinding(StrictModel):
    """Expected deployed address at one compiler-declared library link range."""

    source_path: str = Field(min_length=1, max_length=4_096)
    library_name: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z_$][A-Za-z0-9_$]{0,199}$",
    )
    address: str = Field(pattern=_ADDRESS_PATTERN)
    start: int = Field(ge=0, le=24_575)
    length: Literal[20]

    @field_validator("source_path")
    @classmethod
    def source_path_is_normalized_and_non_sensitive(cls, value: str) -> str:
        return _normalized_solidity_path(value)


class SnapshotImmutableBinding(StrictModel):
    """Expected deployed bytes at one compiler-declared immutable range."""

    identifier: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$",
    )
    start: int = Field(ge=0, le=24_575)
    length: int = Field(ge=1, le=1_024)
    value: str = Field(min_length=4, max_length=2_050, pattern=r"^0x[0-9a-f]+$")

    @model_validator(mode="after")
    def value_matches_declared_length(self) -> SnapshotImmutableBinding:
        if len(self.value) != 2 + self.length * 2:
            raise ValueError("immutable value length does not match its declared byte range")
        return self


class SnapshotSourceBinding(StrictModel):
    """Hash-only source/artifact identity; source contents are never embedded."""

    source_path: str = Field(min_length=1, max_length=4_096)
    contract_name: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z_$][A-Za-z0-9_$]{0,199}$",
    )
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    compiler_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    compiler: SnapshotCompilerBinding
    libraries: list[SnapshotLibraryBinding] = Field(max_length=1_000)
    immutables: list[SnapshotImmutableBinding] = Field(max_length=10_000)

    @field_validator("source_path")
    @classmethod
    def source_path_is_normalized_and_non_sensitive(cls, value: str) -> str:
        return _normalized_solidity_path(value)

    @model_validator(mode="after")
    def variable_ranges_are_sorted_unique_and_disjoint(self) -> SnapshotSourceBinding:
        library_keys = [
            (item.source_path, item.library_name, item.start) for item in self.libraries
        ]
        immutable_keys = [(item.identifier, item.start) for item in self.immutables]
        if library_keys != sorted(set(library_keys)):
            raise ValueError("snapshot library bindings must be unique and sorted")
        if immutable_keys != sorted(set(immutable_keys)):
            raise ValueError("snapshot immutable bindings must be unique and sorted")
        ranges = [
            *((item.start, item.length) for item in self.libraries),
            *((item.start, item.length) for item in self.immutables),
        ]
        occupied: set[int] = set()
        for start, length in ranges:
            current = set(range(start, start + length))
            if occupied & current:
                raise ValueError("snapshot library and immutable ranges must not overlap")
            occupied.update(current)
        return self


class SnapshotContract(StrictModel):
    """Observed deployed runtime code plus optional hash-only source identity."""

    address: str = Field(pattern=_ADDRESS_PATTERN)
    label: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z_$][A-Za-z0-9_$.-]{0,199}$",
    )
    runtime_bytecode: str = Field(
        min_length=4,
        max_length=_MAX_RUNTIME_BYTECODE_HEX_LENGTH,
        pattern=_BYTECODE_PATTERN,
    )
    runtime_bytecode_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_binding: SnapshotSourceBinding | None

    @model_validator(mode="after")
    def bytecode_hash_matches_observation(self) -> SnapshotContract:
        observed = hashlib.sha256(bytes.fromhex(self.runtime_bytecode[2:])).hexdigest()
        if self.runtime_bytecode_sha256 != observed:
            raise ValueError("runtime bytecode hash does not match observed bytecode")
        if self.source_binding is not None:
            bytecode_length = (len(self.runtime_bytecode) - 2) // 2
            if any(
                item.start + item.length > bytecode_length for item in self.source_binding.libraries
            ) or any(
                item.start + item.length > bytecode_length
                for item in self.source_binding.immutables
            ):
                raise ValueError("snapshot variable bytecode range exceeds deployed code")
        return self


class SnapshotProxy(StrictModel):
    """Observed proxy relationship and standardized storage-slot evidence."""

    proxy_address: str = Field(pattern=_ADDRESS_PATTERN)
    kind: ProxyKind
    implementation_address: str = Field(pattern=_ADDRESS_PATTERN)
    admin_address: str | None = Field(pattern=_ADDRESS_PATTERN)
    beacon_address: str | None = Field(pattern=_ADDRESS_PATTERN)
    implementation_slot: str | None = Field(pattern=_BYTES32_PATTERN)
    admin_slot: str | None = Field(pattern=_BYTES32_PATTERN)
    beacon_slot: str | None = Field(pattern=_BYTES32_PATTERN)

    @model_validator(mode="after")
    def proxy_shape_matches_kind(self) -> SnapshotProxy:
        if self.proxy_address == self.implementation_address:
            raise ValueError("proxy and implementation addresses must differ")
        if self.kind is ProxyKind.TRANSPARENT and self.admin_address is None:
            raise ValueError("transparent proxy snapshots require an admin address")
        if self.kind is ProxyKind.BEACON and self.beacon_address is None:
            raise ValueError("beacon proxy snapshots require a beacon address")
        if self.kind is ProxyKind.MINIMAL and any(
            value is not None
            for value in (
                self.admin_address,
                self.beacon_address,
                self.admin_slot,
                self.beacon_slot,
            )
        ):
            raise ValueError("minimal proxy snapshots cannot declare admin or beacon state")
        return self


class SnapshotRoleAssignment(StrictModel):
    """Observed membership for one role on one deployed contract."""

    contract_address: str = Field(pattern=_ADDRESS_PATTERN)
    role_id: str = Field(pattern=_BYTES32_PATTERN)
    role_label: str = Field(
        min_length=1,
        max_length=100,
        pattern=r"^[A-Z][A-Z0-9_]{0,99}$",
    )
    admin_role_id: str | None = Field(pattern=_BYTES32_PATTERN)
    members: list[str] = Field(max_length=10_000)

    @field_validator("members")
    @classmethod
    def members_are_canonical_and_sorted(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)) or any(
            re.fullmatch(_ADDRESS_PATTERN, member) is None for member in value
        ):
            raise ValueError("snapshot role members must be lowercase, unique, and sorted")
        return value


class SnapshotTimelock(StrictModel):
    """Observed governance delay and actor sets."""

    contract_address: str = Field(pattern=_ADDRESS_PATTERN)
    minimum_delay_seconds: int = Field(ge=0, le=2**64 - 1)
    proposers: list[str] = Field(min_length=1, max_length=10_000)
    executors: list[str] = Field(min_length=1, max_length=10_000)
    cancellers: list[str] = Field(max_length=10_000)

    @field_validator("proposers", "executors", "cancellers")
    @classmethod
    def actors_are_canonical_and_sorted(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)) or any(
            re.fullmatch(_ADDRESS_PATTERN, actor) is None for actor in value
        ):
            raise ValueError("snapshot timelock actors must be lowercase, unique, and sorted")
        return value


class SnapshotOracle(StrictModel):
    """Observed feed configuration and freshness state."""

    consumer_address: str = Field(pattern=_ADDRESS_PATTERN)
    feed_address: str = Field(pattern=_ADDRESS_PATTERN)
    feed_decimals: int = Field(ge=0, le=255)
    heartbeat_seconds: int = Field(ge=1, le=2**64 - 1)
    observed_answer: int = Field(ge=-(2**255), le=2**255 - 1)
    updated_at: int = Field(ge=0, le=2**64 - 1)
    sequencer_feed_address: str | None = Field(pattern=_ADDRESS_PATTERN)
    sequencer_grace_period_seconds: int | None = Field(
        ge=0,
        le=2**64 - 1,
    )

    @model_validator(mode="after")
    def sequencer_fields_are_paired(self) -> SnapshotOracle:
        if (self.sequencer_feed_address is None) != (self.sequencer_grace_period_seconds is None):
            raise ValueError("sequencer feed and grace period must be declared together")
        return self


class SnapshotBalance(StrictModel):
    """Observed native or token balance at the pinned block."""

    account_address: str = Field(pattern=_ADDRESS_PATTERN)
    asset_address: str | None = Field(pattern=_ADDRESS_PATTERN)
    amount: int = Field(ge=0, le=2**256 - 1)
    decimals: int = Field(ge=0, le=255)
    symbol: str = Field(
        min_length=1,
        max_length=32,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$",
    )


class SnapshotConfiguration(StrictModel):
    """One canonical non-secret configuration observation."""

    contract_address: str = Field(pattern=_ADDRESS_PATTERN)
    key: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,199}$",
    )
    kind: ConfigurationValueKind
    value: str = Field(min_length=1, max_length=100)
    storage_slot: str | None = Field(pattern=_BYTES32_PATTERN)

    @field_validator("key")
    @classmethod
    def key_is_not_secret_bearing(cls, value: str) -> str:
        separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
        normalized = re.sub(r"[^a-z0-9]+", "_", separated.lower()).strip("_")
        if any(pattern.search(normalized) for pattern in _SENSITIVE_CONFIGURATION_PATTERNS):
            raise ValueError("secret-bearing configuration keys are prohibited")
        return value

    @model_validator(mode="after")
    def value_matches_declared_kind(self) -> SnapshotConfiguration:
        valid = False
        if self.kind is ConfigurationValueKind.UINT:
            valid = _canonical_unsigned(self.value, maximum=2**256 - 1)
        elif self.kind is ConfigurationValueKind.INT:
            valid = _canonical_signed(
                self.value,
                minimum=-(2**255),
                maximum=2**255 - 1,
            )
        elif self.kind is ConfigurationValueKind.BOOL:
            valid = self.value in {"false", "true"}
        elif self.kind is ConfigurationValueKind.ADDRESS:
            valid = re.fullmatch(_ADDRESS_PATTERN, self.value) is not None
        elif self.kind is ConfigurationValueKind.BYTES32:
            valid = re.fullmatch(_BYTES32_PATTERN, self.value) is not None
        if not valid:
            raise ValueError("snapshot configuration value is not canonical for its kind")
        return self


class DeploymentSnapshotPayload(StrictModel):
    """Complete offline state before the canonical self-hash is attached."""

    schema_version: Literal["1.0"]
    format: Literal["mmaudit-offline-deployment"]
    snapshot_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    capture_source: SnapshotCaptureSource
    contains_source_code: Literal[False]
    contains_secrets: Literal[False]
    chain: SnapshotChain
    contracts: list[SnapshotContract] = Field(min_length=1, max_length=10_000)
    proxies: list[SnapshotProxy] = Field(max_length=10_000)
    roles: list[SnapshotRoleAssignment] = Field(max_length=100_000)
    timelocks: list[SnapshotTimelock] = Field(max_length=10_000)
    oracles: list[SnapshotOracle] = Field(max_length=10_000)
    balances: list[SnapshotBalance] = Field(max_length=100_000)
    configuration: list[SnapshotConfiguration] = Field(
        max_length=100_000,
    )

    @field_validator("contains_source_code", "contains_secrets", mode="before")
    @classmethod
    def prohibited_content_flags_are_strict_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("offline snapshots cannot declare source code or secrets")
        return False

    @model_validator(mode="after")
    def observations_are_sorted_linked_and_block_bound(
        self,
    ) -> DeploymentSnapshotPayload:
        contract_addresses = [item.address for item in self.contracts]
        _require_sorted_unique(contract_addresses, "snapshot contract addresses")
        known_contracts = set(contract_addresses)

        proxy_keys = [item.proxy_address for item in self.proxies]
        _require_sorted_unique(proxy_keys, "snapshot proxy addresses")
        for proxy in self.proxies:
            referenced = {
                proxy.proxy_address,
                proxy.implementation_address,
                *([proxy.beacon_address] if proxy.beacon_address is not None else []),
            }
            if not referenced <= known_contracts:
                raise ValueError("snapshot proxy references unbound deployed code")

        role_keys = [(item.contract_address, item.role_id) for item in self.roles]
        _require_sorted_unique(role_keys, "snapshot role bindings")
        timelock_keys = [item.contract_address for item in self.timelocks]
        _require_sorted_unique(timelock_keys, "snapshot timelock addresses")
        oracle_keys = [(item.consumer_address, item.feed_address) for item in self.oracles]
        _require_sorted_unique(oracle_keys, "snapshot oracle bindings")
        balance_keys = [(item.asset_address or "", item.account_address) for item in self.balances]
        _require_sorted_unique(balance_keys, "snapshot balance bindings")
        configuration_keys = [(item.contract_address, item.key) for item in self.configuration]
        _require_sorted_unique(configuration_keys, "snapshot configuration bindings")

        referenced_contracts = {
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
            raise ValueError("snapshot observation references unbound deployed code")
        if any(item.updated_at > self.chain.block_timestamp for item in self.oracles):
            raise ValueError("snapshot oracle update cannot follow the pinned block timestamp")
        return self


class DeploymentSnapshot(DeploymentSnapshotPayload):
    """Canonical, self-hashed offline deployment snapshot."""

    snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def self_hash_matches_contents(self) -> DeploymentSnapshot:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"snapshot_sha256"}))
        if self.snapshot_sha256 != expected:
            raise ValueError("deployment snapshot self-hash does not match its canonical contents")
        return self


def seal_deployment_snapshot(payload: DeploymentSnapshotPayload) -> DeploymentSnapshot:
    """Attach a deterministic self-hash to an already validated payload."""

    serialized = payload.model_dump(mode="json")
    return DeploymentSnapshot.model_validate(
        {
            **serialized,
            "snapshot_sha256": canonical_sha256(serialized),
        }
    )


def load_deployment_snapshot(path: Path) -> DeploymentSnapshot:
    """Load one bounded local snapshot without following links or sensitive filenames."""

    if is_sensitive_workspace_path(path):
        raise ValueError("refusing to read a sensitive snapshot filename")
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("deployment snapshot must be a regular non-link file")
    if path.stat().st_size > _MAX_SNAPSHOT_BYTES:
        raise ValueError("deployment snapshot exceeds the 20 MB limit")
    return DeploymentSnapshot.model_validate_json(path.read_text(encoding="utf-8"))


def write_deployment_snapshot(path: Path, snapshot: DeploymentSnapshot) -> None:
    """Write a canonical snapshot without following a link or shared hardlink."""

    if is_sensitive_workspace_path(path):
        raise ValueError("refusing to write a sensitive snapshot filename")
    if path.is_symlink() or path.is_junction():
        raise ValueError("deployment snapshot destination may not be a link")
    if path.exists() and (not path.is_file() or path.stat().st_nlink != 1):
        raise ValueError("deployment snapshot destination must be an unshared regular file")
    write_json(path, snapshot)


def _canonical_unsigned(value: str, *, maximum: int) -> bool:
    if re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None:
        return False
    return int(value) <= maximum


def _canonical_signed(value: str, *, minimum: int, maximum: int) -> bool:
    if re.fullmatch(r"(?:0|-?[1-9][0-9]*)", value) is None:
        return False
    parsed = int(value)
    return minimum <= parsed <= maximum


def _normalized_solidity_path(value: str) -> str:
    normalized = normalize_relative_path(value)
    normalized_path = PurePosixPath(normalized)
    if (
        normalized in {"", "."}
        or normalized_path.suffix.lower() != ".sol"
        or is_sensitive_workspace_path(normalized_path)
    ):
        raise ValueError("snapshot source binding must identify a non-sensitive Solidity path")
    return normalized


def _require_sorted_unique[SortableT: (str, tuple[str, str])](
    values: list[SortableT],
    label: str,
) -> None:
    if values != sorted(set(values)):
        raise ValueError(f"{label} must be unique and sorted")
