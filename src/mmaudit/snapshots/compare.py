"""Deterministic comparison of local compiler artifacts with offline snapshots."""

from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import write_json
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_path
from mmaudit.snapshots.schema import (
    DeploymentSnapshot,
    SnapshotCompilerBinding,
    SnapshotImmutableBinding,
    SnapshotLibraryBinding,
)

_ADDRESS_PATTERN = r"^0x[0-9a-f]{40}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_ARTIFACT_BYTES = 50_000_000
_MAX_DEPLOYED_BYTECODE_BYTES = 24_576
_MAX_ARTIFACT_INPUTS = 1_000
_MAX_CONTRACT_PROJECTIONS = 10_000


class SnapshotComparisonStatus(StrEnum):
    MATCHED = "matched"
    MISMATCHED = "mismatched"
    INCONCLUSIVE = "inconclusive"


class CompilerLibraryReference(StrictModel):
    source_path: str = Field(min_length=1, max_length=4_096)
    library_name: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z_$][A-Za-z0-9_$]{0,199}$",
    )
    start: int = Field(ge=0, le=24_575)
    length: int = Field(ge=1, le=1_024)
    configured_address: str | None = Field(pattern=_ADDRESS_PATTERN)

    @field_validator("source_path")
    @classmethod
    def source_path_is_safe(cls, value: str) -> str:
        return _normalized_solidity_path(value)


class CompilerImmutableReference(StrictModel):
    identifier: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$",
    )
    start: int = Field(ge=0, le=24_575)
    length: int = Field(ge=1, le=1_024)


class CompilerContractArtifact(StrictModel):
    """Bounded comparison projection from one local compiler artifact."""

    artifact_path: str = Field(min_length=1, max_length=4_096)
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_path: str = Field(min_length=1, max_length=4_096)
    contract_name: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z_$][A-Za-z0-9_$]{0,199}$",
    )
    deployed_bytecode: str = Field(
        min_length=4,
        max_length=2 + _MAX_DEPLOYED_BYTECODE_BYTES * 2,
        pattern=r"^0x(?:[0-9a-f]{2})+$",
    )
    compiler: SnapshotCompilerBinding
    library_references: list[CompilerLibraryReference] = Field(max_length=1_000)
    immutable_references: list[CompilerImmutableReference] = Field(max_length=10_000)

    @field_validator("artifact_path")
    @classmethod
    def artifact_path_is_safe(cls, value: str) -> str:
        normalized = normalize_relative_path(value)
        if normalized in {"", "."} or PurePosixPath(normalized).suffix.lower() != ".json":
            raise ValueError("compiler artifact path must be a normalized JSON path")
        if is_sensitive_workspace_path(normalized):
            raise ValueError("compiler artifact path is sensitive")
        return normalized

    @field_validator("source_path")
    @classmethod
    def source_path_is_safe(cls, value: str) -> str:
        return _normalized_solidity_path(value)

    @model_validator(mode="after")
    def references_are_sorted_unique_and_in_range(self) -> CompilerContractArtifact:
        library_keys = [
            (item.source_path, item.library_name, item.start, item.length)
            for item in self.library_references
        ]
        immutable_keys = [
            (item.identifier, item.start, item.length) for item in self.immutable_references
        ]
        if library_keys != sorted(set(library_keys)):
            raise ValueError("compiler library references must be unique and sorted")
        if immutable_keys != sorted(set(immutable_keys)):
            raise ValueError("compiler immutable references must be unique and sorted")
        bytecode_length = (len(self.deployed_bytecode) - 2) // 2
        ranges = [
            *((item.start, item.length) for item in self.library_references),
            *((item.start, item.length) for item in self.immutable_references),
        ]
        occupied: set[int] = set()
        for start, length in ranges:
            if start + length > bytecode_length:
                raise ValueError("compiler bytecode reference exceeds deployed bytecode")
            current = set(range(start, start + length))
            if occupied & current:
                raise ValueError("compiler bytecode references must not overlap")
            occupied.update(current)
        return self


class CompilerSettingDifference(StrictModel):
    field: str = Field(
        min_length=1,
        max_length=100,
        pattern=r"^[a-z][a-z0-9_]{0,99}$",
    )
    expected: str = Field(max_length=500)
    observed: str = Field(max_length=500)


class LibraryLinkComparison(StrictModel):
    source_path: str
    library_name: str
    start: int = Field(ge=0)
    length: int = Field(ge=1)
    snapshot_address: str | None = Field(pattern=_ADDRESS_PATTERN)
    compiler_address: str | None = Field(pattern=_ADDRESS_PATTERN)
    deployed_value: str | None = Field(default=None, pattern=r"^0x[0-9a-f]+$")
    reference_present: bool
    matched: bool


class ImmutableValueComparison(StrictModel):
    identifier: str
    start: int = Field(ge=0)
    length: int = Field(ge=1)
    expected_value: str | None = Field(default=None, pattern=r"^0x[0-9a-f]+$")
    deployed_value: str | None = Field(default=None, pattern=r"^0x[0-9a-f]+$")
    reference_present: bool
    matched: bool


class ContractSnapshotComparison(StrictModel):
    address: str = Field(pattern=_ADDRESS_PATTERN)
    source_path: str
    contract_name: str
    snapshot_runtime_bytecode_sha256: str = Field(pattern=_SHA256_PATTERN)
    expected_compiler_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    observed_compiler_artifact_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    artifact_hash_match: bool
    bytecode_length_match: bool
    bytecode_match: bool
    compiler_setting_differences: list[CompilerSettingDifference]
    library_links: list[LibraryLinkComparison]
    immutables: list[ImmutableValueComparison]
    matched: bool
    limitation: str | None = Field(default=None, max_length=1_000)

    @model_validator(mode="after")
    def result_is_consistent(self) -> ContractSnapshotComparison:
        expected = (
            self.limitation is None
            and self.artifact_hash_match
            and self.bytecode_length_match
            and self.bytecode_match
            and not self.compiler_setting_differences
            and all(item.matched for item in self.library_links)
            and all(item.matched for item in self.immutables)
        )
        if self.matched != expected:
            raise ValueError("contract snapshot comparison result is inconsistent")
        return self


class DeploymentSnapshotComparisonPayload(StrictModel):
    schema_version: str = Field(pattern=r"^1\.0$")
    snapshot_id: str
    snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    chain_id: int = Field(ge=1)
    block_number: int = Field(ge=0)
    status: SnapshotComparisonStatus
    contracts_expected: int = Field(ge=0)
    contracts_compared: int = Field(ge=0)
    contracts_matched: int = Field(ge=0)
    comparisons: list[ContractSnapshotComparison] = Field(max_length=10_000)
    limitations: list[str] = Field(max_length=10_000)

    @model_validator(mode="after")
    def counts_and_status_are_consistent(self) -> DeploymentSnapshotComparisonPayload:
        addresses = [item.address for item in self.comparisons]
        if addresses != sorted(set(addresses)):
            raise ValueError("snapshot contract comparisons must be unique and sorted")
        if self.limitations != sorted(set(self.limitations)):
            raise ValueError("snapshot comparison limitations must be unique and sorted")
        if self.contracts_compared != sum(item.limitation is None for item in self.comparisons):
            raise ValueError("snapshot compared-contract count is inconsistent")
        if self.contracts_matched != sum(item.matched for item in self.comparisons):
            raise ValueError("snapshot matched-contract count is inconsistent")
        if self.contracts_expected != len(self.comparisons):
            raise ValueError("snapshot expected-contract count is inconsistent")
        expected_status = (
            SnapshotComparisonStatus.INCONCLUSIVE
            if self.limitations or any(item.limitation is not None for item in self.comparisons)
            else (
                SnapshotComparisonStatus.MATCHED
                if all(item.matched for item in self.comparisons) and self.comparisons
                else SnapshotComparisonStatus.MISMATCHED
            )
        )
        if self.status is not expected_status:
            raise ValueError("snapshot comparison status is inconsistent")
        return self


class DeploymentSnapshotComparisonReport(DeploymentSnapshotComparisonPayload):
    report_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def report_hash_matches_contents(self) -> DeploymentSnapshotComparisonReport:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"report_sha256"}))
        if self.report_sha256 != expected:
            raise ValueError("snapshot comparison report hash is inconsistent")
        return self


def load_compiler_contract_artifacts(
    repository_root: Path,
    artifact_paths: list[Path],
) -> list[CompilerContractArtifact]:
    """Read explicit local artifact files without executing repository code."""

    root = repository_root.resolve(strict=True)
    results: list[CompilerContractArtifact] = []
    normalized_inputs: list[tuple[str, Path]] = []
    if len(artifact_paths) > _MAX_ARTIFACT_INPUTS:
        raise ValueError("too many compiler artifact inputs")
    for raw_path in artifact_paths:
        candidate = raw_path if raw_path.is_absolute() else root / raw_path
        if _path_contains_link(candidate, root):
            raise ValueError("compiler artifacts must be regular non-link files")
        resolved = candidate.resolve(strict=True)
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError("compiler artifact escaped the selected repository root") from exc
        normalized_inputs.append((normalize_relative_path(relative), resolved))
    if [item[0] for item in normalized_inputs] != sorted(
        set(item[0] for item in normalized_inputs)
    ):
        raise ValueError("compiler artifact inputs must be unique and sorted")
    for relative, path in normalized_inputs:
        if (
            not path.is_file()
            or is_sensitive_workspace_path(path)
            or path.stat().st_size > _MAX_ARTIFACT_BYTES
        ):
            raise ValueError("compiler artifact is sensitive, missing, or oversized")
        raw = path.read_bytes()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ValueError("compiler artifact must be bounded UTF-8 JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("compiler artifact root must be an object")
        results.extend(
            _artifact_projections(
                payload,
                artifact_path=relative,
                artifact_sha256=hashlib.sha256(raw).hexdigest(),
            )
        )
        if len(results) > _MAX_CONTRACT_PROJECTIONS:
            raise ValueError("compiler artifact contract projection limit exceeded")
    keys = [(item.source_path, item.contract_name) for item in results]
    if keys != sorted(set(keys)):
        raise ValueError("compiler artifact contract projections must be unique and sorted")
    return results


def compare_deployment_snapshot(
    snapshot: DeploymentSnapshot,
    artifacts: list[CompilerContractArtifact],
) -> DeploymentSnapshotComparisonReport:
    """Compare source-bound contracts using only typed local snapshot/artifact state."""

    artifact_by_contract = {
        (artifact.source_path, artifact.contract_name): artifact for artifact in artifacts
    }
    if len(artifact_by_contract) != len(artifacts):
        raise ValueError("compiler artifact comparison keys must be unique")
    comparisons: list[ContractSnapshotComparison] = []
    limitations: list[str] = []
    for contract in snapshot.contracts:
        binding = contract.source_binding
        if binding is None:
            continue
        artifact = artifact_by_contract.get((binding.source_path, binding.contract_name))
        if artifact is None:
            limitation = (
                f"{binding.source_path}:{binding.contract_name}: compiler artifact unavailable"
            )
            limitations.append(limitation)
            comparisons.append(
                ContractSnapshotComparison(
                    address=contract.address,
                    source_path=binding.source_path,
                    contract_name=binding.contract_name,
                    snapshot_runtime_bytecode_sha256=contract.runtime_bytecode_sha256,
                    expected_compiler_artifact_sha256=binding.compiler_artifact_sha256,
                    artifact_hash_match=False,
                    bytecode_length_match=False,
                    bytecode_match=False,
                    compiler_setting_differences=[],
                    library_links=[],
                    immutables=[],
                    matched=False,
                    limitation=limitation,
                )
            )
            continue
        snapshot_bytes = bytes.fromhex(contract.runtime_bytecode[2:])
        artifact_bytes = bytes.fromhex(artifact.deployed_bytecode[2:])
        ranges = {
            *((item.start, item.length) for item in binding.libraries),
            *((item.start, item.length) for item in binding.immutables),
            *((item.start, item.length) for item in artifact.library_references),
            *((item.start, item.length) for item in artifact.immutable_references),
        }
        bytecode_length_match = len(snapshot_bytes) == len(artifact_bytes)
        bytecode_match = bytecode_length_match and _masked_bytecode(
            snapshot_bytes,
            ranges,
        ) == _masked_bytecode(artifact_bytes, ranges)
        library_links = _compare_library_links(snapshot_bytes, binding.libraries, artifact)
        immutables = _compare_immutables(snapshot_bytes, binding.immutables, artifact)
        compiler_differences = _compiler_differences(binding.compiler, artifact.compiler)
        artifact_hash_match = binding.compiler_artifact_sha256 == artifact.artifact_sha256
        matched = (
            artifact_hash_match
            and bytecode_length_match
            and bytecode_match
            and not compiler_differences
            and all(item.matched for item in library_links)
            and all(item.matched for item in immutables)
        )
        comparisons.append(
            ContractSnapshotComparison(
                address=contract.address,
                source_path=binding.source_path,
                contract_name=binding.contract_name,
                snapshot_runtime_bytecode_sha256=contract.runtime_bytecode_sha256,
                expected_compiler_artifact_sha256=binding.compiler_artifact_sha256,
                observed_compiler_artifact_sha256=artifact.artifact_sha256,
                artifact_hash_match=artifact_hash_match,
                bytecode_length_match=bytecode_length_match,
                bytecode_match=bytecode_match,
                compiler_setting_differences=compiler_differences,
                library_links=library_links,
                immutables=immutables,
                matched=matched,
            )
        )
    comparisons.sort(key=lambda item: item.address)
    if not comparisons:
        limitations.append("snapshot contains no source-bound contracts to compare")
    status = (
        SnapshotComparisonStatus.INCONCLUSIVE
        if limitations or any(item.limitation is not None for item in comparisons)
        else (
            SnapshotComparisonStatus.MATCHED
            if all(item.matched for item in comparisons) and comparisons
            else SnapshotComparisonStatus.MISMATCHED
        )
    )
    payload = DeploymentSnapshotComparisonPayload(
        schema_version="1.0",
        snapshot_id=snapshot.snapshot_id,
        snapshot_sha256=snapshot.snapshot_sha256,
        chain_id=snapshot.chain.chain_id,
        block_number=snapshot.chain.block_number,
        status=status,
        contracts_expected=len(comparisons),
        contracts_compared=sum(item.limitation is None for item in comparisons),
        contracts_matched=sum(item.matched for item in comparisons),
        comparisons=comparisons,
        limitations=sorted(set(limitations)),
    )
    serialized = payload.model_dump(mode="json")
    return DeploymentSnapshotComparisonReport.model_validate(
        {
            **serialized,
            "report_sha256": canonical_sha256(serialized),
        }
    )


def write_snapshot_comparison(
    path: Path,
    report: DeploymentSnapshotComparisonReport,
) -> None:
    if path.is_symlink() or path.is_junction():
        raise ValueError("snapshot comparison destination may not be a link")
    if path.exists() and (not path.is_file() or path.stat().st_nlink != 1):
        raise ValueError("snapshot comparison destination must be an unshared regular file")
    write_json(path, report)


def _artifact_projections(
    payload: dict[str, Any],
    *,
    artifact_path: str,
    artifact_sha256: str,
) -> list[CompilerContractArtifact]:
    if isinstance(payload.get("contractName"), str):
        return [
            _direct_artifact_projection(
                payload,
                artifact_path=artifact_path,
                artifact_sha256=artifact_sha256,
            )
        ]
    output = payload.get("output")
    contracts = output.get("contracts") if isinstance(output, dict) else None
    if not isinstance(contracts, dict):
        raise ValueError("compiler artifact contains no contract output")
    settings = payload.get("input", {}).get("settings")
    if not isinstance(settings, dict):
        raise ValueError("build-info artifact omits compiler settings")
    projections: list[CompilerContractArtifact] = []
    for source_path, source_contracts in sorted(contracts.items()):
        if not isinstance(source_path, str) or not isinstance(source_contracts, dict):
            raise ValueError("build-info contract map is malformed")
        for contract_name, contract_payload in sorted(source_contracts.items()):
            if not isinstance(contract_name, str) or not isinstance(contract_payload, dict):
                raise ValueError("build-info contract payload is malformed")
            metadata = _metadata_object(contract_payload.get("metadata"))
            compiler_version = _compiler_version(metadata, payload)
            deployed = contract_payload.get("evm", {}).get("deployedBytecode")
            projections.append(
                _projection(
                    artifact_path=artifact_path,
                    artifact_sha256=artifact_sha256,
                    source_path=source_path,
                    contract_name=contract_name,
                    deployed=deployed,
                    compiler_version=compiler_version,
                    settings=settings,
                )
            )
    return projections


def _direct_artifact_projection(
    payload: dict[str, Any],
    *,
    artifact_path: str,
    artifact_sha256: str,
) -> CompilerContractArtifact:
    metadata = _metadata_object(payload.get("metadata"))
    settings = metadata.get("settings")
    if not isinstance(settings, dict):
        raise ValueError("compiler artifact metadata omits settings")
    source_path = payload.get("sourceName")
    contract_name = payload.get("contractName")
    if not isinstance(source_path, str) or not isinstance(contract_name, str):
        raise ValueError("compiler artifact omits source or contract identity")
    deployed = payload.get("deployedBytecode")
    if deployed is None and isinstance(payload.get("evm"), dict):
        deployed = payload["evm"].get("deployedBytecode")
    return _projection(
        artifact_path=artifact_path,
        artifact_sha256=artifact_sha256,
        source_path=source_path,
        contract_name=contract_name,
        deployed=deployed,
        compiler_version=_compiler_version(metadata, payload),
        settings=settings,
    )


def _projection(
    *,
    artifact_path: str,
    artifact_sha256: str,
    source_path: str,
    contract_name: str,
    deployed: object,
    compiler_version: str,
    settings: dict[str, Any],
) -> CompilerContractArtifact:
    if not isinstance(deployed, dict):
        raise ValueError("compiler artifact omits deployed bytecode")
    raw_object = deployed.get("object")
    if not isinstance(raw_object, str):
        raise ValueError("compiler artifact omits deployed bytecode object")
    libraries = _library_references(deployed.get("linkReferences"), settings)
    immutables = _immutable_references(deployed.get("immutableReferences"))
    bytecode = _normalized_template_bytecode(
        raw_object,
        [
            *((item.start, item.length) for item in libraries),
            *((item.start, item.length) for item in immutables),
        ],
    )
    return CompilerContractArtifact(
        artifact_path=artifact_path,
        artifact_sha256=artifact_sha256,
        source_path=source_path,
        contract_name=contract_name,
        deployed_bytecode=bytecode,
        compiler=_compiler_binding(compiler_version, settings),
        library_references=libraries,
        immutable_references=immutables,
    )


def _metadata_object(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and len(value.encode("utf-8")) <= 5_000_000:
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise ValueError("compiler metadata is not valid JSON") from exc
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("compiler artifact metadata is unavailable")


def _compiler_version(metadata: dict[str, Any], outer: dict[str, Any]) -> str:
    compiler = metadata.get("compiler")
    version = compiler.get("version") if isinstance(compiler, dict) else None
    if isinstance(version, str):
        return version
    for key in ("solcLongVersion", "solcVersion"):
        version = outer.get(key)
        if isinstance(version, str):
            return version
    raise ValueError("compiler artifact omits compiler version")


def _compiler_binding(
    compiler_version: str,
    settings: dict[str, Any],
) -> SnapshotCompilerBinding:
    optimizer = settings.get("optimizer")
    metadata = settings.get("metadata")
    if not isinstance(optimizer, dict) or not isinstance(metadata, dict):
        raise ValueError("compiler artifact omits optimizer or metadata settings")
    enabled = optimizer.get("enabled")
    runs = optimizer.get("runs", 0)
    evm_version = settings.get("evmVersion")
    via_ir = settings.get("viaIR", False)
    bytecode_hash = metadata.get("bytecodeHash")
    if (
        not isinstance(enabled, bool)
        or not isinstance(runs, int)
        or isinstance(runs, bool)
        or not isinstance(evm_version, str)
        or not isinstance(via_ir, bool)
        or not isinstance(bytecode_hash, str)
    ):
        raise ValueError("compiler settings projection is malformed")
    return SnapshotCompilerBinding(
        compiler_version=compiler_version,
        evm_version=evm_version,
        optimizer_enabled=enabled,
        optimizer_runs=runs if enabled else 0,
        via_ir=via_ir,
        metadata_bytecode_hash=bytecode_hash,
        settings_sha256=canonical_sha256(settings),
    )


def _library_references(
    value: object,
    settings: dict[str, Any],
) -> list[CompilerLibraryReference]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("compiler library references are malformed")
    configured = settings.get("libraries", {})
    if not isinstance(configured, dict):
        raise ValueError("compiler library settings are malformed")
    references: list[CompilerLibraryReference] = []
    for source_path, libraries in sorted(value.items()):
        if not isinstance(source_path, str) or not isinstance(libraries, dict):
            raise ValueError("compiler library reference map is malformed")
        configured_source = configured.get(source_path, {})
        if not isinstance(configured_source, dict):
            configured_source = {}
        for library_name, ranges in sorted(libraries.items()):
            if not isinstance(library_name, str) or not isinstance(ranges, list):
                raise ValueError("compiler library ranges are malformed")
            address = configured_source.get(library_name)
            normalized_address: str | None = None
            if isinstance(address, str) and re.fullmatch(
                r"0x[0-9a-fA-F]{40}",
                address,
            ):
                normalized_address = address.lower()
            for raw_range in ranges:
                start, length = _reference_range(raw_range)
                references.append(
                    CompilerLibraryReference(
                        source_path=source_path,
                        library_name=library_name,
                        start=start,
                        length=length,
                        configured_address=normalized_address,
                    )
                )
    return sorted(
        references,
        key=lambda item: (item.source_path, item.library_name, item.start, item.length),
    )


def _immutable_references(value: object) -> list[CompilerImmutableReference]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("compiler immutable references are malformed")
    references: list[CompilerImmutableReference] = []
    for identifier, ranges in sorted(value.items()):
        if not isinstance(identifier, str) or not isinstance(ranges, list):
            raise ValueError("compiler immutable reference map is malformed")
        for raw_range in ranges:
            start, length = _reference_range(raw_range)
            references.append(
                CompilerImmutableReference(
                    identifier=identifier,
                    start=start,
                    length=length,
                )
            )
    return sorted(references, key=lambda item: (item.identifier, item.start, item.length))


def _reference_range(value: object) -> tuple[int, int]:
    if not isinstance(value, dict):
        raise ValueError("compiler bytecode reference must be an object")
    start = value.get("start")
    length = value.get("length")
    if (
        not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(length, int)
        or isinstance(length, bool)
        or start < 0
        or length <= 0
    ):
        raise ValueError("compiler bytecode reference range is invalid")
    return start, length


def _normalized_template_bytecode(
    value: str,
    ranges: list[tuple[int, int]],
) -> str:
    raw = value.removeprefix("0x")
    if not raw or len(raw) % 2 or len(raw) > _MAX_DEPLOYED_BYTECODE_BYTES * 2:
        raise ValueError("compiler deployed bytecode is empty, odd, or oversized")
    characters = list(raw.lower())
    for start, length in ranges:
        end = (start + length) * 2
        if end > len(characters):
            raise ValueError("compiler bytecode reference exceeds deployed bytecode")
        characters[start * 2 : end] = "0" * (length * 2)
    normalized = "".join(characters)
    if re.fullmatch(r"[0-9a-f]+", normalized) is None:
        raise ValueError("compiler deployed bytecode contains an unbound placeholder")
    return "0x" + normalized


def _compiler_differences(
    expected: SnapshotCompilerBinding,
    observed: SnapshotCompilerBinding,
) -> list[CompilerSettingDifference]:
    fields = (
        "compiler_version",
        "evm_version",
        "optimizer_enabled",
        "optimizer_runs",
        "via_ir",
        "metadata_bytecode_hash",
        "settings_sha256",
    )
    differences = []
    for field in fields:
        expected_value = getattr(expected, field)
        observed_value = getattr(observed, field)
        if expected_value != observed_value:
            differences.append(
                CompilerSettingDifference(
                    field=field,
                    expected=json.dumps(expected_value, sort_keys=True),
                    observed=json.dumps(observed_value, sort_keys=True),
                )
            )
    return differences


def _compare_library_links(
    deployed: bytes,
    expected: list[SnapshotLibraryBinding],
    artifact: CompilerContractArtifact,
) -> list[LibraryLinkComparison]:
    expected_by_key: dict[
        tuple[str, str, int, int],
        SnapshotLibraryBinding,
    ] = {
        (item.source_path, item.library_name, item.start, int(item.length)): item
        for item in expected
    }
    observed_by_key = {
        (item.source_path, item.library_name, item.start, item.length): item
        for item in artifact.library_references
    }
    results = []
    for key in sorted(set(expected_by_key) | set(observed_by_key)):
        source_path, library_name, start, length = key
        snapshot_binding = expected_by_key.get(key)
        compiler_reference = observed_by_key.get(key)
        deployed_value = _deployed_range(deployed, start, length)
        snapshot_address = snapshot_binding.address if snapshot_binding is not None else None
        compiler_address = (
            compiler_reference.configured_address if compiler_reference is not None else None
        )
        matched = (
            snapshot_address is not None
            and compiler_address is not None
            and compiler_reference is not None
            and deployed_value == snapshot_address
            and compiler_address == snapshot_address
        )
        results.append(
            LibraryLinkComparison(
                source_path=source_path,
                library_name=library_name,
                start=start,
                length=length,
                snapshot_address=snapshot_address,
                compiler_address=compiler_address,
                deployed_value=deployed_value,
                reference_present=compiler_reference is not None,
                matched=matched,
            )
        )
    return results


def _compare_immutables(
    deployed: bytes,
    expected: list[SnapshotImmutableBinding],
    artifact: CompilerContractArtifact,
) -> list[ImmutableValueComparison]:
    expected_by_key = {(item.identifier, item.start, item.length): item for item in expected}
    observed_keys = {
        (item.identifier, item.start, item.length) for item in artifact.immutable_references
    }
    results = []
    for key in sorted(set(expected_by_key) | observed_keys):
        identifier, start, length = key
        snapshot_binding = expected_by_key.get(key)
        deployed_value = _deployed_range(deployed, start, length)
        expected_value = snapshot_binding.value if snapshot_binding is not None else None
        reference_present = key in observed_keys
        results.append(
            ImmutableValueComparison(
                identifier=identifier,
                start=start,
                length=length,
                expected_value=expected_value,
                deployed_value=deployed_value,
                reference_present=reference_present,
                matched=(
                    reference_present
                    and expected_value is not None
                    and expected_value == deployed_value
                ),
            )
        )
    return results


def _deployed_range(deployed: bytes, start: int, length: int) -> str | None:
    if start + length > len(deployed):
        return None
    return "0x" + deployed[start : start + length].hex()


def _masked_bytecode(
    bytecode: bytes,
    ranges: set[tuple[int, int]],
) -> bytes:
    masked = bytearray(bytecode)
    for start, length in sorted(ranges):
        if start + length > len(masked):
            return b""
        masked[start : start + length] = b"\0" * length
    return bytes(masked)


def _normalized_solidity_path(value: str) -> str:
    normalized = normalize_relative_path(value)
    path = PurePosixPath(normalized)
    if (
        normalized in {"", "."}
        or path.suffix.lower() != ".sol"
        or is_sensitive_workspace_path(path)
    ):
        raise ValueError("compiler source path must be a non-sensitive Solidity path")
    return normalized


def _path_contains_link(candidate: Path, root: Path) -> bool:
    current = candidate
    while True:
        if current.is_symlink() or current.is_junction():
            return True
        if current == root or current == current.parent:
            return False
        current = current.parent
