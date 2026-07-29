"""Strict reconciliation of Forge test lists with pinned-solc AST build information.

The parser in this module is deliberately pure: callers supply already-bounded
bytes and source contents, and the parser performs no filesystem access or
subprocess execution.  The resulting inventory binds every Forge execution
selector to the effective Solidity declaration selected by the compiler's
linearized inheritance order.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from mmaudit.models.schemas import StrictModel
from mmaudit.repository.ignore import normalize_relative_path

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SOLIDITY_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_FORGE_SELECTOR = re.compile(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:\((?P<parameters>[^()]*)\))?$")
_SOURCE_LOCATION = re.compile(r"^(?P<start>[0-9]+):(?P<length>[0-9]+):(?P<file>[0-9]+)$")
_ARRAY_SUFFIX = re.compile(r"^(?P<base>.+?)(?P<suffix>(?:\[[0-9]*\])+)$")
_ARRAY_PART = re.compile(r"\[[0-9]*\]")
_LOCATION_SUFFIX = re.compile(r"\s+(?:memory|calldata|storage)(?:\s+(?:pointer|ref))?$")
_INTEGER_TYPE = re.compile(r"^(?P<signed>u?int)(?P<bits>[0-9]*)$")
_FIXED_BYTES_TYPE = re.compile(r"^bytes(?P<size>[0-9]+)$")


class FoundryInventoryError(ValueError):
    """Raised when compiler and Forge inventory evidence cannot be reconciled."""


class FoundryInventoryLimits(StrictModel):
    """Explicit ceilings for untrusted Forge and compiler JSON evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_forge_json_bytes: int = Field(default=10_000_000, ge=1_024, le=100_000_000)
    max_build_info_json_bytes: int = Field(
        default=50_000_000,
        ge=1_024,
        le=250_000_000,
    )
    max_build_info_files: int = Field(default=64, ge=1, le=1_000)
    max_sources: int = Field(default=100_000, ge=1, le=1_000_000)
    max_source_bytes: int = Field(default=20_000_000, ge=1, le=100_000_000)
    max_total_source_bytes: int = Field(
        default=500_000_000,
        ge=1_024,
        le=2_000_000_000,
    )
    max_ast_nodes: int = Field(default=1_000_000, ge=1, le=10_000_000)
    max_contracts: int = Field(default=100_000, ge=1, le=1_000_000)
    max_functions: int = Field(default=1_000_000, ge=1, le=10_000_000)
    max_inheritance_depth: int = Field(default=1_000, ge=1, le=100_000)
    max_suites: int = Field(default=10_000, ge=1, le=100_000)
    max_tests: int = Field(default=100_000, ge=1, le=1_000_000)


@dataclass(frozen=True, slots=True)
class FoundrySourceInput:
    """Caller-supplied source content and its independently observed digest."""

    path: str
    content: bytes
    source_sha256: str


class FoundryInventorySourceBinding(StrictModel):
    """Hash-only binding for one compiler input source."""

    path: str = Field(min_length=1, max_length=4_096)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)

    @field_validator("path")
    @classmethod
    def path_is_canonical(cls, value: str) -> str:
        return _normalized_source_path(value)


class FoundryTestDeclaration(StrictModel):
    """One Forge selector bound to its effective compiler declaration."""

    schema_version: Literal["1.0"] = "1.0"
    project_root: str = Field(min_length=1, max_length=4_096)
    execution_path: str = Field(min_length=1, max_length=4_096)
    execution_suite_name: str = Field(min_length=1, max_length=500)
    test_name: str = Field(min_length=1, max_length=500)
    test_signature: str = Field(min_length=1, max_length=2_000)
    declaration_signature: str = Field(min_length=1, max_length=2_000)
    declaration_path: str = Field(min_length=1, max_length=4_096)
    declaration_contract: str = Field(min_length=1, max_length=500)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    execution_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_start_line: int = Field(ge=1)
    execution_end_line: int = Field(ge=1)
    execution_contract_ast_id: int = Field(ge=0)
    declaration_contract_ast_id: int = Field(ge=0)
    function_ast_id: int = Field(ge=0)
    build_info_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> FoundryTestDeclaration:
        """Validate and self-hash a declaration binding."""

        if "record_sha256" in values:
            raise ValueError("record_sha256 is derived")
        provisional = cls.model_construct(**values, record_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"record_sha256"})
        return cls.model_validate(
            {
                **payload,
                "record_sha256": _canonical_sha256(payload),
            }
        )

    @field_validator("execution_path", "declaration_path")
    @classmethod
    def paths_are_canonical(cls, value: str) -> str:
        return _normalized_source_path(value)

    @field_validator("project_root")
    @classmethod
    def project_root_is_canonical(cls, value: str) -> str:
        return _normalized_project_root(value)

    @field_validator("execution_suite_name", "declaration_contract", "test_name")
    @classmethod
    def contract_names_are_identifiers(cls, value: str) -> str:
        if _SOLIDITY_IDENTIFIER.fullmatch(value) is None:
            raise ValueError("Foundry inventory name is not a Solidity identifier")
        return value

    @field_validator("test_signature", "declaration_signature")
    @classmethod
    def signatures_are_safe(cls, value: str) -> str:
        _parse_forge_selector(value)
        return value

    @model_validator(mode="after")
    def range_and_hash_are_consistent(self) -> Self:
        selector_name, _ = _parse_forge_selector(self.test_signature)
        declaration_name, explicit = _parse_forge_selector(self.declaration_signature)
        if self.test_name != selector_name or self.test_name != declaration_name or not explicit:
            raise ValueError("Foundry declaration names or signature are inconsistent")
        if self.end_line < self.start_line or self.execution_end_line < self.execution_start_line:
            raise ValueError("Foundry source range is reversed")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"record_sha256"}))
        if self.record_sha256 != expected:
            raise ValueError("Foundry inventory record self-hash is inconsistent")
        return self

    @property
    def canonical_key(self) -> tuple[str, str, str]:
        """Return the exact execution identity emitted by Forge."""

        return (self.execution_path, self.execution_suite_name, self.test_signature)


class FoundryTestInventory(StrictModel):
    """Canonical, self-hashed reconciliation of real compiler and Forge evidence."""

    schema_version: Literal["1.0"] = "1.0"
    project_root: str = Field(min_length=1, max_length=4_096)
    forge_list_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    compiler_version: str = Field(min_length=1, max_length=1_000)
    compiler_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    build_info_sha256s: tuple[str, ...] = Field(min_length=1, max_length=1_000)
    sources: tuple[FoundryInventorySourceBinding, ...] = Field(
        min_length=1,
        max_length=1_000_000,
    )
    suite_count: int = Field(ge=1)
    test_count: int = Field(ge=1)
    tests: tuple[FoundryTestDeclaration, ...] = Field(
        min_length=1,
        max_length=1_000_000,
    )
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> FoundryTestInventory:
        """Validate and self-hash a completed inventory."""

        if "inventory_sha256" in values:
            raise ValueError("inventory_sha256 is derived")
        provisional = cls.model_construct(**values, inventory_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"inventory_sha256"})
        return cls.model_validate(
            {
                **payload,
                "inventory_sha256": _canonical_sha256(payload),
            }
        )

    @field_validator("compiler_version")
    @classmethod
    def compiler_version_is_safe(cls, value: str) -> str:
        if (
            value != value.strip()
            or unicodedata.normalize("NFC", value) != value
            or any(unicodedata.category(character).startswith("C") for character in value)
        ):
            raise ValueError("compiler version is not canonical printable text")
        return value

    @field_validator("project_root")
    @classmethod
    def project_root_is_canonical(cls, value: str) -> str:
        return _normalized_project_root(value)

    @model_validator(mode="after")
    def order_counts_and_hash_are_consistent(self) -> Self:
        if self.build_info_sha256s != tuple(sorted(set(self.build_info_sha256s))):
            raise ValueError("build-info hashes must be unique and canonically ordered")
        source_paths = tuple(source.path for source in self.sources)
        if source_paths != tuple(sorted(set(source_paths))):
            raise ValueError("inventory sources must be unique and canonically ordered")
        keys = tuple(test.canonical_key for test in self.tests)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("inventory tests must be unique and canonically ordered")
        if any(test.project_root != self.project_root for test in self.tests):
            raise ValueError("inventory record project roots differ from their inventory")
        suites = {(test.execution_path, test.execution_suite_name) for test in self.tests}
        if self.suite_count != len(suites) or self.test_count != len(self.tests):
            raise ValueError("inventory counts differ from its bound declarations")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"inventory_sha256"}))
        if self.inventory_sha256 != expected:
            raise ValueError("Foundry inventory self-hash is inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class _Function:
    ast_id: int
    contract_ast_id: int
    name: str
    signature: str
    path: str
    source_sha256: str
    start_line: int
    end_line: int
    visibility: str
    implemented: bool


@dataclass(frozen=True, slots=True)
class _Contract:
    ast_id: int
    name: str
    path: str
    source_sha256: str
    start_line: int
    end_line: int
    abstract: bool
    linearized_base_contracts: tuple[int, ...]
    functions: tuple[_Function, ...]


@dataclass(frozen=True, slots=True)
class _BuildUnit:
    build_info_sha256: str
    contracts_by_id: Mapping[int, _Contract]
    contracts_by_path_name: Mapping[tuple[str, str], _Contract]


@dataclass(frozen=True, slots=True)
class _ForgeSuite:
    path: str
    contract: str
    selectors: tuple[str, ...]


def parse_foundry_test_inventory(
    *,
    forge_list_json: bytes,
    build_info_jsons: Sequence[bytes],
    sources: Sequence[FoundrySourceInput],
    project_root: str = ".",
    compiler_version: str,
    compiler_sha256: str,
    limits: FoundryInventoryLimits | None = None,
) -> FoundryTestInventory:
    """Reconcile a Forge JSON test list with one or more pinned compiler outputs.

    ``build_info_jsons`` must use the standard compiler build-info envelope with
    ``input.sources``, ``output.sources``, and ``output.contracts``.  Source bytes
    are supplied independently so compiler input content and AST byte ranges can
    be checked without reading the repository.
    """

    bounds = limits or FoundryInventoryLimits()
    normalized_project_root = _normalized_project_root(project_root)
    _validate_compiler_identity(compiler_version, compiler_sha256)
    source_map = _validated_sources(sources, bounds)
    forge_suites = _parse_forge_list(forge_list_json, bounds)
    units, observed_source_paths = _parse_build_units(
        build_info_jsons,
        source_map,
        compiler_version,
        bounds,
    )
    if observed_source_paths != set(source_map):
        missing = sorted(set(source_map) - observed_source_paths)
        extra = sorted(observed_source_paths - set(source_map))
        raise FoundryInventoryError(
            f"caller/compiler source inventories differ (missing={missing!r}, extra={extra!r})"
        )

    declarations = _reconcile_forge_suites(
        forge_suites,
        units,
        normalized_project_root,
        bounds,
    )
    bindings = tuple(
        FoundryInventorySourceBinding(
            path=path,
            source_sha256=source.source_sha256,
            size_bytes=len(source.content),
        )
        for path, source in sorted(source_map.items())
    )
    build_hashes = tuple(sorted(unit.build_info_sha256 for unit in units))
    return FoundryTestInventory.sealed(
        project_root=normalized_project_root,
        forge_list_sha256=hashlib.sha256(forge_list_json).hexdigest(),
        compiler_version=compiler_version,
        compiler_sha256=compiler_sha256,
        build_info_sha256s=build_hashes,
        sources=bindings,
        suite_count=len(forge_suites),
        test_count=len(declarations),
        tests=tuple(sorted(declarations, key=lambda item: item.canonical_key)),
    )


def _validate_compiler_identity(version: str, sha256: str) -> None:
    if (
        not isinstance(version, str)
        or not version
        or version != version.strip()
        or len(version) > 1_000
        or unicodedata.normalize("NFC", version) != version
        or any(unicodedata.category(character).startswith("C") for character in version)
    ):
        raise FoundryInventoryError("compiler version is not canonical printable text")
    if not isinstance(sha256, str) or _SHA256_PATTERN.fullmatch(sha256) is None:
        raise FoundryInventoryError("compiler SHA-256 is invalid")


def _validated_sources(
    sources: Sequence[FoundrySourceInput],
    limits: FoundryInventoryLimits,
) -> dict[str, FoundrySourceInput]:
    if not sources:
        raise FoundryInventoryError("source inventory is empty")
    if len(sources) > limits.max_sources:
        raise FoundryInventoryError("source inventory exceeds its file ceiling")
    result: dict[str, FoundrySourceInput] = {}
    total_bytes = 0
    for source in sources:
        if not isinstance(source, FoundrySourceInput):
            raise FoundryInventoryError("source inventory contains an invalid record")
        path = _normalized_source_path(source.path)
        if path != source.path:
            raise FoundryInventoryError("source path is not canonical")
        if path in result:
            raise FoundryInventoryError(f"source inventory contains duplicate path: {path}")
        if type(source.content) is not bytes:
            raise FoundryInventoryError(f"source content is not bytes: {path}")
        if len(source.content) > limits.max_source_bytes:
            raise FoundryInventoryError(f"source exceeds its byte ceiling: {path}")
        total_bytes += len(source.content)
        if total_bytes > limits.max_total_source_bytes:
            raise FoundryInventoryError("source inventory exceeds its total byte ceiling")
        try:
            source.content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FoundryInventoryError(f"source is not valid UTF-8: {path}") from exc
        observed = hashlib.sha256(source.content).hexdigest()
        if (
            not isinstance(source.source_sha256, str)
            or _SHA256_PATTERN.fullmatch(source.source_sha256) is None
            or source.source_sha256 != observed
        ):
            raise FoundryInventoryError(f"source hash is inconsistent: {path}")
        result[path] = source
    return result


def _parse_forge_list(raw: bytes, limits: FoundryInventoryLimits) -> tuple[_ForgeSuite, ...]:
    payload = _decode_json_object(
        raw,
        label="Forge test list",
        maximum_bytes=limits.max_forge_json_bytes,
    )
    suites: list[_ForgeSuite] = []
    test_count = 0
    for raw_path, raw_contracts in payload.items():
        path = _normalized_source_path(_expect_string(raw_path, "Forge test path"))
        contracts = _expect_object(raw_contracts, f"Forge suites for {path}")
        if not contracts:
            raise FoundryInventoryError(f"Forge test path contains no suites: {path}")
        for raw_contract, raw_tests in contracts.items():
            contract = _expect_identifier(raw_contract, "Forge suite name")
            if not isinstance(raw_tests, list) or not raw_tests:
                raise FoundryInventoryError(
                    f"Forge suite test list is not a non-empty array: {path}:{contract}"
                )
            selectors: list[str] = []
            for raw_selector in raw_tests:
                selector = _expect_string(raw_selector, "Forge test selector")
                name, _ = _parse_forge_selector(selector)
                if not _is_test_name(name):
                    raise FoundryInventoryError(
                        f"Forge emitted a non-test selector: {path}:{contract}:{selector}"
                    )
                selectors.append(selector)
                test_count += 1
                if test_count > limits.max_tests:
                    raise FoundryInventoryError("Forge test inventory exceeds its test ceiling")
            if selectors != sorted(set(selectors)):
                raise FoundryInventoryError(
                    f"Forge suite selectors are duplicated or not canonical: {path}:{contract}"
                )
            suites.append(_ForgeSuite(path=path, contract=contract, selectors=tuple(selectors)))
            if len(suites) > limits.max_suites:
                raise FoundryInventoryError("Forge test inventory exceeds its suite ceiling")
    if not suites:
        raise FoundryInventoryError("Forge test list is empty")
    keys = [(suite.path, suite.contract) for suite in suites]
    if keys != sorted(set(keys)):
        raise FoundryInventoryError("Forge suites are duplicated or not canonically ordered")
    return tuple(suites)


def _parse_build_units(
    raw_build_infos: Sequence[bytes],
    sources: Mapping[str, FoundrySourceInput],
    compiler_version: str,
    limits: FoundryInventoryLimits,
) -> tuple[tuple[_BuildUnit, ...], set[str]]:
    if not raw_build_infos:
        raise FoundryInventoryError("compiler build-info inventory is empty")
    if len(raw_build_infos) > limits.max_build_info_files:
        raise FoundryInventoryError("compiler build-info inventory exceeds its file ceiling")
    units: list[_BuildUnit] = []
    hashes: set[str] = set()
    observed_source_paths: set[str] = set()
    total_nodes = 0
    total_contracts = 0
    total_functions = 0
    for index, raw in enumerate(raw_build_infos):
        build_hash = hashlib.sha256(raw).hexdigest()
        if build_hash in hashes:
            raise FoundryInventoryError("compiler build-info inventory contains duplicate content")
        hashes.add(build_hash)
        payload = _decode_json_object(
            raw,
            label=f"compiler build info {index}",
            maximum_bytes=limits.max_build_info_json_bytes,
        )
        if payload.get("_format") != "ethers-rs-sol-build-info-1":
            raise FoundryInventoryError("build-info format is not the pinned Foundry envelope")
        if payload.get("language") != "Solidity":
            raise FoundryInventoryError("build-info language is not Solidity")
        recorded_version = payload.get("solcVersion")
        if not isinstance(recorded_version, str) or recorded_version != compiler_version:
            raise FoundryInventoryError("build-info compiler version differs from pinned compiler")
        long_version = payload.get("solcLongVersion")
        if not isinstance(long_version, str) or not long_version.startswith(recorded_version):
            raise FoundryInventoryError("build-info long compiler version is malformed")
        build_id = payload.get("id")
        if not isinstance(build_id, str) or re.fullmatch(r"[0-9a-f]{16,64}", build_id) is None:
            raise FoundryInventoryError("build-info identifier is malformed")
        input_payload = _expect_object(payload.get("input"), "build-info input")
        if input_payload.get("language") != "Solidity":
            raise FoundryInventoryError("build-info input language is not Solidity")
        if input_payload.get("version") != recorded_version:
            raise FoundryInventoryError("build-info input compiler version is inconsistent")
        input_sources = _expect_object(input_payload.get("sources"), "build-info input sources")
        output_payload = _expect_object(payload.get("output"), "build-info output")
        _reject_compiler_errors(output_payload)
        output_sources = _expect_object(
            output_payload.get("sources"),
            "build-info output sources",
        )
        output_contracts = _expect_object(
            output_payload.get("contracts"),
            "build-info output contracts",
        )
        normalized_input = _validate_build_input_sources(input_sources, sources)
        normalized_output = {
            _normalized_source_path(_expect_string(path, "compiler output source path")): value
            for path, value in output_sources.items()
        }
        if set(normalized_input) != set(normalized_output):
            raise FoundryInventoryError("build-info input and output source paths differ")
        normalized_contract_payloads = {
            _normalized_source_path(_expect_string(path, "compiler contract source path")): value
            for path, value in output_contracts.items()
        }
        _validate_source_id_mapping(payload.get("source_id_to_path"), normalized_output)
        if not set(normalized_contract_payloads).issubset(normalized_input):
            raise FoundryInventoryError("build-info contract path is absent from compiler inputs")
        observed_source_paths.update(normalized_input)
        unit, node_count, contract_count, function_count = _parse_build_unit(
            build_hash,
            normalized_output,
            normalized_contract_payloads,
            sources,
            limits,
        )
        total_nodes += node_count
        total_contracts += contract_count
        total_functions += function_count
        if total_nodes > limits.max_ast_nodes:
            raise FoundryInventoryError("compiler AST inventory exceeds its node ceiling")
        if total_contracts > limits.max_contracts:
            raise FoundryInventoryError("compiler AST inventory exceeds its contract ceiling")
        if total_functions > limits.max_functions:
            raise FoundryInventoryError("compiler AST inventory exceeds its function ceiling")
        units.append(unit)
    return tuple(units), observed_source_paths


def _validate_build_input_sources(
    raw_sources: Mapping[str, Any],
    sources: Mapping[str, FoundrySourceInput],
) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for raw_path, raw_item in raw_sources.items():
        path = _normalized_source_path(_expect_string(raw_path, "compiler input source path"))
        if path in result:
            raise FoundryInventoryError(f"normalized compiler source path is duplicated: {path}")
        item = _expect_object(raw_item, f"compiler input source {path}")
        if set(item) != {"content"} or not isinstance(item.get("content"), str):
            raise FoundryInventoryError(
                f"compiler input source must contain only UTF-8 content: {path}"
            )
        supplied = sources.get(path)
        if supplied is None:
            raise FoundryInventoryError(f"compiler input source was not supplied by caller: {path}")
        try:
            encoded = item["content"].encode("utf-8")
        except UnicodeEncodeError as exc:
            raise FoundryInventoryError(
                f"compiler input source is not valid UTF-8: {path}"
            ) from exc
        if encoded != supplied.content:
            raise FoundryInventoryError(
                f"compiler input content differs from caller source: {path}"
            )
        result[path] = item
    if not result:
        raise FoundryInventoryError("build-info compiler input contains no sources")
    return result


def _reject_compiler_errors(output: Mapping[str, Any]) -> None:
    raw_errors = output.get("errors", [])
    if not isinstance(raw_errors, list):
        raise FoundryInventoryError("build-info compiler errors field is malformed")
    for item in raw_errors:
        diagnostic = _expect_object(item, "compiler diagnostic")
        severity = diagnostic.get("severity")
        if not isinstance(severity, str):
            raise FoundryInventoryError("compiler diagnostic severity is malformed")
        if severity == "error":
            raise FoundryInventoryError("build-info contains a compiler error")


def _validate_source_id_mapping(
    raw_mapping: Any,
    output_sources: Mapping[str, Any],
) -> None:
    mapping = _expect_object(raw_mapping, "build-info source ID mapping")
    observed: dict[int, str] = {}
    for raw_id, raw_path in mapping.items():
        if not isinstance(raw_id, str) or re.fullmatch(r"0|[1-9][0-9]*", raw_id) is None:
            raise FoundryInventoryError("build-info source ID mapping key is malformed")
        source_id = int(raw_id)
        path = _normalized_source_path(
            _expect_string(raw_path, "build-info source ID mapping path")
        )
        if source_id in observed:
            raise FoundryInventoryError("build-info source ID mapping is duplicated")
        observed[source_id] = path
    expected = {
        _expect_nonnegative_int(
            _expect_object(raw_item, f"compiler output source {path}").get("id"),
            f"source ID for {path}",
        ): path
        for path, raw_item in output_sources.items()
    }
    if len(expected) != len(output_sources):
        raise FoundryInventoryError("compiler output source IDs are duplicated")
    if observed != expected:
        raise FoundryInventoryError("build-info source ID mapping differs from output sources")


def _parse_build_unit(
    build_hash: str,
    raw_sources: Mapping[str, Any],
    raw_contract_outputs: Mapping[str, Any],
    sources: Mapping[str, FoundrySourceInput],
    limits: FoundryInventoryLimits,
) -> tuple[_BuildUnit, int, int, int]:
    source_ids: dict[int, str] = {}
    contract_nodes: list[tuple[str, Mapping[str, Any]]] = []
    ast_ids: set[int] = set()
    node_count = 0
    for path, raw_item in sorted(raw_sources.items()):
        item = _expect_object(raw_item, f"compiler output source {path}")
        source_id = _expect_nonnegative_int(item.get("id"), f"source ID for {path}")
        if source_id in source_ids:
            raise FoundryInventoryError("compiler source IDs are duplicated")
        source_ids[source_id] = path
        ast = _expect_object(item.get("ast"), f"source AST for {path}")
        if ast.get("nodeType") != "SourceUnit":
            raise FoundryInventoryError(f"compiler source AST is not a SourceUnit: {path}")
        source_unit_ast_id = _expect_nonnegative_int(ast.get("id"), f"SourceUnit AST ID for {path}")
        _record_ast_id(source_unit_ast_id, ast_ids)
        _validated_span(ast.get("src"), source_id, sources[path].content, f"SourceUnit {path}")
        raw_nodes = ast.get("nodes")
        if not isinstance(raw_nodes, list):
            raise FoundryInventoryError(f"SourceUnit nodes are malformed: {path}")
        node_count += 1 + len(raw_nodes)
        if node_count > limits.max_ast_nodes:
            raise FoundryInventoryError("compiler AST inventory exceeds its node ceiling")
        for node in raw_nodes:
            if not isinstance(node, dict):
                raise FoundryInventoryError(f"SourceUnit contains a malformed node: {path}")
            if node.get("nodeType") == "ContractDefinition":
                contract_nodes.append((path, node))

    contracts_by_id: dict[int, _Contract] = {}
    contracts_by_path_name: dict[tuple[str, str], _Contract] = {}
    function_count = 0
    for path, node in contract_nodes:
        contract, functions_seen = _parse_contract(
            path,
            node,
            source_ids,
            sources,
            ast_ids,
            limits,
        )
        if contract.ast_id in contracts_by_id:
            raise FoundryInventoryError("compiler contract AST IDs are duplicated")
        key = (contract.path, contract.name)
        if key in contracts_by_path_name:
            raise FoundryInventoryError(
                f"compiler contract identity is duplicated: {contract.path}:{contract.name}"
            )
        contracts_by_id[contract.ast_id] = contract
        contracts_by_path_name[key] = contract
        function_count += functions_seen

    for contract in contracts_by_id.values():
        linearized = contract.linearized_base_contracts
        if (
            not linearized
            or linearized[0] != contract.ast_id
            or len(linearized) != len(set(linearized))
            or len(linearized) > limits.max_inheritance_depth
            or any(base_id not in contracts_by_id for base_id in linearized)
        ):
            raise FoundryInventoryError(
                f"contract linearization is malformed: {contract.path}:{contract.name}"
            )

    _validate_contract_outputs(raw_contract_outputs, contracts_by_id)
    return (
        _BuildUnit(
            build_info_sha256=build_hash,
            contracts_by_id=contracts_by_id,
            contracts_by_path_name=contracts_by_path_name,
        ),
        node_count + function_count,
        len(contracts_by_id),
        function_count,
    )


def _parse_contract(
    path: str,
    node: Mapping[str, Any],
    source_ids: Mapping[int, str],
    sources: Mapping[str, FoundrySourceInput],
    ast_ids: set[int],
    limits: FoundryInventoryLimits,
) -> tuple[_Contract, int]:
    ast_id = _expect_nonnegative_int(node.get("id"), f"contract AST ID in {path}")
    _record_ast_id(ast_id, ast_ids)
    name = _expect_identifier(node.get("name"), f"contract name in {path}")
    abstract = node.get("abstract")
    if type(abstract) is not bool:
        raise FoundryInventoryError(f"contract abstract flag is malformed: {path}:{name}")
    if node.get("contractKind") not in {"contract", "interface", "library"}:
        raise FoundryInventoryError(f"contract kind is malformed: {path}:{name}")
    source_id, contract_start, contract_end = _validated_span_for_path(
        node.get("src"),
        path,
        source_ids,
        sources,
        f"contract {path}:{name}",
    )
    del source_id
    contract_start_line, contract_end_line = _span_lines(
        sources[path].content,
        contract_start,
        contract_end,
    )
    raw_linearized = node.get("linearizedBaseContracts")
    if not isinstance(raw_linearized, list):
        raise FoundryInventoryError(f"contract linearization is missing: {path}:{name}")
    linearized = tuple(
        _expect_nonnegative_int(value, f"linearized base ID for {path}:{name}")
        for value in raw_linearized
    )
    raw_nodes = node.get("nodes")
    if not isinstance(raw_nodes, list):
        raise FoundryInventoryError(f"contract nodes are malformed: {path}:{name}")
    functions: list[_Function] = []
    function_signatures: set[str] = set()
    function_count = 0
    for child in raw_nodes:
        if not isinstance(child, dict):
            raise FoundryInventoryError(f"contract contains a malformed node: {path}:{name}")
        if child.get("nodeType") != "FunctionDefinition":
            continue
        function_count += 1
        if function_count > limits.max_functions:
            raise FoundryInventoryError("compiler AST inventory exceeds its function ceiling")
        function = _parse_function(
            path,
            name,
            ast_id,
            child,
            source_ids,
            sources,
            ast_ids,
            contract_start,
            contract_end,
        )
        if function is None:
            continue
        if function.signature in function_signatures:
            raise FoundryInventoryError(
                f"contract contains duplicate function signature: {path}:{name}:"
                f"{function.signature}"
            )
        function_signatures.add(function.signature)
        functions.append(function)
    functions.sort(key=lambda item: (item.signature, item.ast_id))
    return (
        _Contract(
            ast_id=ast_id,
            name=name,
            path=path,
            source_sha256=sources[path].source_sha256,
            start_line=contract_start_line,
            end_line=contract_end_line,
            abstract=abstract,
            linearized_base_contracts=linearized,
            functions=tuple(functions),
        ),
        function_count,
    )


def _parse_function(
    path: str,
    contract_name: str,
    contract_ast_id: int,
    node: Mapping[str, Any],
    source_ids: Mapping[int, str],
    sources: Mapping[str, FoundrySourceInput],
    ast_ids: set[int],
    contract_start: int,
    contract_end: int,
) -> _Function | None:
    ast_id = _expect_nonnegative_int(
        node.get("id"),
        f"function AST ID in {path}:{contract_name}",
    )
    _record_ast_id(ast_id, ast_ids)
    if node.get("kind") != "function":
        return None
    name = _expect_identifier(node.get("name"), f"function name in {path}:{contract_name}")
    visibility = node.get("visibility")
    if visibility not in {"public", "external", "internal", "private"}:
        raise FoundryInventoryError(
            f"function visibility is malformed: {path}:{contract_name}:{name}"
        )
    implemented = node.get("implemented")
    if type(implemented) is not bool:
        raise FoundryInventoryError(
            f"function implementation flag is malformed: {path}:{contract_name}:{name}"
        )
    scope = node.get("scope")
    if scope is not None and (
        _expect_nonnegative_int(scope, f"function scope for {path}:{contract_name}:{name}")
        != contract_ast_id
    ):
        raise FoundryInventoryError(
            f"function scope differs from containing contract: {path}:{contract_name}:{name}"
        )
    _, start, end = _validated_span_for_path(
        node.get("src"),
        path,
        source_ids,
        sources,
        f"function {path}:{contract_name}:{name}",
    )
    if start < contract_start or end > contract_end:
        raise FoundryInventoryError(
            f"function source range escapes containing contract: {path}:{contract_name}:{name}"
        )
    if not _is_test_name(name):
        return None
    signature = _function_signature(node, path, contract_name, name)
    start_line, end_line = _span_lines(sources[path].content, start, end)
    return _Function(
        ast_id=ast_id,
        contract_ast_id=contract_ast_id,
        name=name,
        signature=signature,
        path=path,
        source_sha256=sources[path].source_sha256,
        start_line=start_line,
        end_line=end_line,
        visibility=visibility,
        implemented=implemented,
    )


def _function_signature(
    node: Mapping[str, Any],
    path: str,
    contract_name: str,
    name: str,
) -> str:
    parameters = _expect_object(
        node.get("parameters"),
        f"function parameters for {path}:{contract_name}:{name}",
    )
    raw_parameters = parameters.get("parameters")
    if not isinstance(raw_parameters, list):
        raise FoundryInventoryError(
            f"function parameter list is malformed: {path}:{contract_name}:{name}"
        )
    canonical: list[str] = []
    for parameter in raw_parameters:
        item = _expect_object(
            parameter,
            f"function parameter for {path}:{contract_name}:{name}",
        )
        type_descriptions = _expect_object(
            item.get("typeDescriptions"),
            f"function type description for {path}:{contract_name}:{name}",
        )
        type_string = _expect_string(
            type_descriptions.get("typeString"),
            f"function parameter type for {path}:{contract_name}:{name}",
        )
        canonical.append(_canonical_abi_type(type_string))
    return f"{name}({','.join(canonical)})"


def _canonical_abi_type(raw_type: str) -> str:
    value = _LOCATION_SUFFIX.sub("", raw_type.strip())
    array_match = _ARRAY_SUFFIX.fullmatch(value)
    if array_match is not None:
        base = _canonical_abi_type(array_match.group("base"))
        suffix = array_match.group("suffix")
        if "".join(_ARRAY_PART.findall(suffix)) != suffix:
            raise FoundryInventoryError(f"unsupported compiler parameter type: {raw_type}")
        return base + suffix
    if value == "address payable":
        return "address"
    if value.startswith("contract "):
        contract_name = value.removeprefix("contract ")
        if _SOLIDITY_IDENTIFIER.fullmatch(contract_name) is None:
            raise FoundryInventoryError(f"unsupported compiler parameter type: {raw_type}")
        return "address"
    integer = _INTEGER_TYPE.fullmatch(value)
    if integer is not None:
        bits = integer.group("bits") or "256"
        parsed_bits = int(bits)
        if parsed_bits < 8 or parsed_bits > 256 or parsed_bits % 8:
            raise FoundryInventoryError(f"invalid compiler integer type: {raw_type}")
        return f"{integer.group('signed')}{parsed_bits}"
    fixed_bytes = _FIXED_BYTES_TYPE.fullmatch(value)
    if fixed_bytes is not None:
        size = int(fixed_bytes.group("size"))
        if not 1 <= size <= 32:
            raise FoundryInventoryError(f"invalid compiler fixed-bytes type: {raw_type}")
        return value
    if value == "byte":
        return "bytes1"
    if value in {"address", "bool", "bytes", "string"}:
        return value
    raise FoundryInventoryError(f"unsupported compiler parameter type: {raw_type}")


def _validate_contract_outputs(
    raw_contract_outputs: Mapping[str, Any],
    contracts_by_id: Mapping[int, _Contract],
) -> None:
    ast_contracts = {
        (contract.path, contract.name): contract for contract in contracts_by_id.values()
    }
    output_contracts: dict[tuple[str, str], Mapping[str, Any]] = {}
    for path, raw_contracts in raw_contract_outputs.items():
        contracts = _expect_object(raw_contracts, f"compiler contracts for {path}")
        for raw_name, raw_payload in contracts.items():
            name = _expect_identifier(raw_name, f"compiler contract name in {path}")
            key = (path, name)
            if key in output_contracts:
                raise FoundryInventoryError(
                    f"compiler output contract identity is duplicated: {path}:{name}"
                )
            output_contracts[key] = _expect_object(
                raw_payload,
                f"compiler output contract {path}:{name}",
            )
    if set(output_contracts) != set(ast_contracts):
        missing_contracts = sorted(set(ast_contracts) - set(output_contracts))
        extra_contracts = sorted(set(output_contracts) - set(ast_contracts))
        raise FoundryInventoryError(
            f"compiler AST/artifact contract inventories differ (missing={missing_contracts!r}, "
            f"extra={extra_contracts!r})"
        )
    for key, contract in ast_contracts.items():
        payload = output_contracts[key]
        raw_abi = payload.get("abi")
        if not isinstance(raw_abi, list):
            raise FoundryInventoryError(
                f"compiler contract ABI is missing or malformed: {contract.path}:{contract.name}"
            )
        observed_test_signatures = _test_signatures_from_abi(
            raw_abi,
            contract.path,
            contract.name,
        )
        expected_test_signatures = set(_effective_test_functions(contract, contracts_by_id))
        if observed_test_signatures != expected_test_signatures:
            missing_functions = sorted(expected_test_signatures - observed_test_signatures)
            extra_functions = sorted(observed_test_signatures - expected_test_signatures)
            raise FoundryInventoryError(
                f"compiler ABI/AST test functions differ for {contract.path}:{contract.name} "
                f"(missing={missing_functions!r}, extra={extra_functions!r})"
            )


def _test_signatures_from_abi(
    raw_abi: list[Any],
    path: str,
    contract_name: str,
) -> set[str]:
    result: set[str] = set()
    for raw_entry in raw_abi:
        entry = _expect_object(raw_entry, f"ABI entry for {path}:{contract_name}")
        entry_type = entry.get("type")
        if not isinstance(entry_type, str):
            raise FoundryInventoryError(f"ABI entry type is malformed: {path}:{contract_name}")
        if entry_type != "function":
            continue
        name = _expect_identifier(entry.get("name"), f"ABI function in {path}:{contract_name}")
        if not _is_test_name(name):
            continue
        raw_inputs = entry.get("inputs")
        if not isinstance(raw_inputs, list):
            raise FoundryInventoryError(
                f"ABI function inputs are malformed: {path}:{contract_name}:{name}"
            )
        types: list[str] = []
        for raw_input in raw_inputs:
            abi_input = _expect_object(
                raw_input,
                f"ABI input for {path}:{contract_name}:{name}",
            )
            abi_type = _expect_string(
                abi_input.get("type"),
                f"ABI input type for {path}:{contract_name}:{name}",
            )
            if not abi_type or any(character.isspace() for character in abi_type):
                raise FoundryInventoryError(
                    f"ABI input type is not canonical: {path}:{contract_name}:{name}"
                )
            types.append(abi_type)
        signature = f"{name}({','.join(types)})"
        if signature in result:
            raise FoundryInventoryError(
                f"ABI contains duplicate test function: {path}:{contract_name}:{signature}"
            )
        result.add(signature)
    return result


def _effective_test_functions(
    contract: _Contract,
    contracts_by_id: Mapping[int, _Contract],
) -> dict[str, _Function]:
    effective: dict[str, _Function] = {}
    for contract_id in contract.linearized_base_contracts:
        declaration_contract = contracts_by_id[contract_id]
        for function in declaration_contract.functions:
            if (
                _is_test_name(function.name)
                and function.visibility in {"public", "external"}
                and function.implemented
            ):
                effective.setdefault(function.signature, function)
    return effective


def _reconcile_forge_suites(
    forge_suites: tuple[_ForgeSuite, ...],
    units: tuple[_BuildUnit, ...],
    project_root: str,
    limits: FoundryInventoryLimits,
) -> list[FoundryTestDeclaration]:
    resolved_suites: dict[tuple[str, str], tuple[_BuildUnit, _Contract]] = {}
    for suite in forge_suites:
        suite_matches = [
            (unit, contract)
            for unit in units
            if (contract := unit.contracts_by_path_name.get((suite.path, suite.contract)))
            is not None
        ]
        if len(suite_matches) != 1:
            raise FoundryInventoryError(
                f"Forge suite does not map to exactly one compiler contract: "
                f"{suite.path}:{suite.contract}"
            )
        unit, contract = suite_matches[0]
        if contract.abstract:
            raise FoundryInventoryError(
                f"Forge suite resolves to an abstract contract: {suite.path}:{suite.contract}"
            )
        resolved_suites[(suite.path, suite.contract)] = (unit, contract)

    compiler_suites: set[tuple[str, str]] = set()
    for unit in units:
        for suite_key, contract in unit.contracts_by_path_name.items():
            if contract.abstract or not _effective_test_functions(
                contract,
                unit.contracts_by_id,
            ):
                continue
            if suite_key in compiler_suites:
                raise FoundryInventoryError(
                    "compiler suite maps to more than one build unit: "
                    f"{suite_key[0]}:{suite_key[1]}"
                )
            compiler_suites.add(suite_key)

    listed_suites = set(resolved_suites)
    if compiler_suites != listed_suites:
        missing_suites = sorted(compiler_suites - listed_suites)
        extra_suites = sorted(listed_suites - compiler_suites)
        raise FoundryInventoryError(
            "Forge/compiler suite inventories differ "
            f"(missing={missing_suites!r}, extra={extra_suites!r})"
        )

    declarations: list[FoundryTestDeclaration] = []
    for suite in forge_suites:
        unit, contract = resolved_suites[(suite.path, suite.contract)]
        effective = _effective_test_functions(contract, unit.contracts_by_id)
        selected: dict[str, _Function] = {}
        for selector in suite.selectors:
            name, has_explicit_parameters = _parse_forge_selector(selector)
            if has_explicit_parameters:
                function_matches = [
                    function for signature, function in effective.items() if signature == selector
                ]
            else:
                function_matches = [
                    function for function in effective.values() if function.name == name
                ]
            if len(function_matches) != 1:
                reason = "ambiguous" if len(function_matches) > 1 else "unknown"
                raise FoundryInventoryError(
                    f"Forge test selector is {reason}: {suite.path}:{suite.contract}:{selector}"
                )
            function = function_matches[0]
            if function.signature in selected:
                raise FoundryInventoryError(
                    f"Forge selectors map to the same declaration: "
                    f"{suite.path}:{suite.contract}:{selector}"
                )
            selected[function.signature] = function
            declaration_contract = unit.contracts_by_id[function.contract_ast_id]
            declarations.append(
                FoundryTestDeclaration.sealed(
                    project_root=project_root,
                    execution_path=suite.path,
                    execution_suite_name=suite.contract,
                    test_name=name,
                    test_signature=selector,
                    declaration_signature=function.signature,
                    declaration_path=function.path,
                    declaration_contract=declaration_contract.name,
                    source_sha256=function.source_sha256,
                    start_line=function.start_line,
                    end_line=function.end_line,
                    execution_source_sha256=contract.source_sha256,
                    execution_start_line=contract.start_line,
                    execution_end_line=contract.end_line,
                    execution_contract_ast_id=contract.ast_id,
                    declaration_contract_ast_id=declaration_contract.ast_id,
                    function_ast_id=function.ast_id,
                    build_info_sha256=unit.build_info_sha256,
                )
            )
            if len(declarations) > limits.max_tests:
                raise FoundryInventoryError("reconciled test inventory exceeds its test ceiling")
        if set(selected) != set(effective):
            missing = sorted(set(effective) - set(selected))
            raise FoundryInventoryError(
                f"Forge omitted effective compiler tests for {suite.path}:{suite.contract}: "
                f"{missing!r}"
            )
    return declarations


def _validated_span_for_path(
    raw: Any,
    expected_path: str,
    source_ids: Mapping[int, str],
    sources: Mapping[str, FoundrySourceInput],
    label: str,
) -> tuple[int, int, int]:
    source_id, start, end = _parse_span(raw, label)
    if source_ids.get(source_id) != expected_path:
        raise FoundryInventoryError(f"{label} source-unit mapping is inconsistent")
    _check_span_bounds(start, end, sources[expected_path].content, label)
    return source_id, start, end


def _validated_span(
    raw: Any,
    expected_source_id: int,
    content: bytes,
    label: str,
) -> tuple[int, int]:
    source_id, start, end = _parse_span(raw, label)
    if source_id != expected_source_id:
        raise FoundryInventoryError(f"{label} source-unit mapping is inconsistent")
    _check_span_bounds(start, end, content, label)
    return start, end


def _parse_span(raw: Any, label: str) -> tuple[int, int, int]:
    value = _expect_string(raw, f"{label} source range")
    match = _SOURCE_LOCATION.fullmatch(value)
    if match is None:
        raise FoundryInventoryError(f"{label} source range is malformed")
    start = int(match.group("start"))
    length = int(match.group("length"))
    source_id = int(match.group("file"))
    return source_id, start, start + length


def _check_span_bounds(start: int, end: int, content: bytes, label: str) -> None:
    if start > len(content) or end < start or end > len(content):
        raise FoundryInventoryError(f"{label} source range exceeds supplied content")


def _span_lines(content: bytes, start: int, end: int) -> tuple[int, int]:
    start_line = content.count(b"\n", 0, start) + 1
    inclusive_end = start if end == start else end - 1
    end_line = content.count(b"\n", 0, inclusive_end) + 1
    return start_line, end_line


def _record_ast_id(ast_id: int, ast_ids: set[int]) -> None:
    if ast_id in ast_ids:
        raise FoundryInventoryError(f"compiler AST ID is duplicated: {ast_id}")
    ast_ids.add(ast_id)


def _parse_forge_selector(value: str) -> tuple[str, bool]:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2_000
        or value != value.strip()
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        raise FoundryInventoryError("Forge test selector is not canonical printable text")
    match = _FORGE_SELECTOR.fullmatch(value)
    if match is None:
        raise FoundryInventoryError(f"Forge test selector is malformed: {value}")
    parameters = match.group("parameters")
    if parameters is not None:
        if any(character.isspace() for character in parameters):
            raise FoundryInventoryError(f"Forge test selector is not canonical: {value}")
        if parameters:
            for parameter in parameters.split(","):
                if _canonical_abi_type(parameter) != parameter:
                    raise FoundryInventoryError(f"Forge test selector is not canonical: {value}")
    return match.group("name"), parameters is not None


def _is_test_name(value: str) -> bool:
    return value.startswith("test") or value.startswith("invariant")


def _normalized_source_path(value: str) -> str:
    if not isinstance(value, str):
        raise FoundryInventoryError("source path is not text")
    try:
        normalized = normalize_relative_path(value)
    except ValueError as exc:
        raise FoundryInventoryError("source path is not a contained POSIX path") from exc
    if (
        not normalized
        or normalized == "."
        or normalized != value
        or "\\" in value
        or value.startswith("-")
        or unicodedata.normalize("NFC", value) != value
    ):
        raise FoundryInventoryError("source path is not a canonical contained POSIX path")
    return normalized


def _normalized_project_root(value: str) -> str:
    if value == ".":
        return value
    return _normalized_source_path(value)


def _expect_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FoundryInventoryError(f"{label} is not an object")
    return value


def _expect_string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise FoundryInventoryError(f"{label} is not text")
    return value


def _expect_identifier(value: Any, label: str) -> str:
    text = _expect_string(value, label)
    if _SOLIDITY_IDENTIFIER.fullmatch(text) is None:
        raise FoundryInventoryError(f"{label} is not a Solidity identifier")
    return text


def _expect_nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise FoundryInventoryError(f"{label} is not a non-negative integer")
    return value


def _decode_json_object(raw: bytes, *, label: str, maximum_bytes: int) -> dict[str, Any]:
    if type(raw) is not bytes:
        raise FoundryInventoryError(f"{label} input is not bytes")
    if not raw or len(raw) > maximum_bytes:
        raise FoundryInventoryError(f"{label} is empty or exceeds its byte ceiling")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise FoundryInventoryError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    def reject_nonfinite(value: str) -> None:
        raise FoundryInventoryError(f"{label} contains non-finite JSON value: {value}")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise FoundryInventoryError(f"{label} contains out-of-range JSON number")
        return parsed

    try:
        payload = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=reject_nonfinite,
            parse_float=finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise FoundryInventoryError(f"{label} is not valid bounded JSON") from exc
    if not isinstance(payload, dict):
        raise FoundryInventoryError(f"{label} must contain one JSON object")
    return payload


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "FoundryInventoryError",
    "FoundryInventoryLimits",
    "FoundryInventorySourceBinding",
    "FoundrySourceInput",
    "FoundryTestDeclaration",
    "FoundryTestInventory",
    "parse_foundry_test_inventory",
]
