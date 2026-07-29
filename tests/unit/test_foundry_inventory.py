from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.scanners.foundry_inventory import (
    FoundryInventoryError,
    FoundryInventoryLimits,
    FoundrySourceInput,
    FoundryTestInventory,
    parse_foundry_test_inventory,
)

_COMPILER_SHA256 = "c" * 64
_COMPILER_VERSION = "0.8.30+commit.73712a01"


@dataclass(frozen=True)
class _FunctionSpec:
    ast_id: int
    name: str
    parameter_types: tuple[str, ...] = ()
    visibility: str = "public"
    implemented: bool = True

    @property
    def signature(self) -> str:
        return f"{self.name}({','.join(self.parameter_types)})"


@dataclass(frozen=True)
class _ContractSpec:
    ast_id: int
    path: str
    name: str
    abstract: bool
    linearized: tuple[int, ...]
    functions: tuple[_FunctionSpec, ...] = ()


def _source_inputs(contents: dict[str, str]) -> tuple[FoundrySourceInput, ...]:
    return tuple(
        FoundrySourceInput(
            path=path,
            content=content.encode(),
            source_sha256=hashlib.sha256(content.encode()).hexdigest(),
        )
        for path, content in sorted(contents.items())
    )


def _span(content: bytes, needle: bytes, occurrence: int = 0) -> str:
    start = -1
    cursor = 0
    for _ in range(occurrence + 1):
        start = content.index(needle, cursor)
        cursor = start + len(needle)
    line_end = content.find(b"\n", start)
    end = len(content) if line_end < 0 else line_end + 1
    return f"{start}:{end - start}"


def _function_node(
    *,
    contract: _ContractSpec,
    function: _FunctionSpec,
    source_id: int,
    content: bytes,
    occurrence: int,
) -> dict[str, Any]:
    location = _span(content, f"function {function.name}".encode(), occurrence)
    return {
        "id": function.ast_id,
        "nodeType": "FunctionDefinition",
        "kind": "function",
        "name": function.name,
        "visibility": function.visibility,
        "implemented": function.implemented,
        "scope": contract.ast_id,
        "src": f"{location}:{source_id}",
        "parameters": {
            "parameters": [
                {"typeDescriptions": {"typeString": parameter}}
                for parameter in function.parameter_types
            ]
        },
    }


def _effective_functions(
    contract: _ContractSpec,
    by_id: dict[int, _ContractSpec],
) -> dict[str, _FunctionSpec]:
    result: dict[str, _FunctionSpec] = {}
    for contract_id in contract.linearized:
        for function in by_id[contract_id].functions:
            if (
                function.name.startswith(("test", "invariant"))
                and function.visibility in {"public", "external"}
                and function.implemented
            ):
                result.setdefault(function.signature, function)
    return result


def _build_info(
    contents: dict[str, str],
    contracts: tuple[_ContractSpec, ...],
    *,
    version: str = _COMPILER_VERSION,
) -> bytes:
    source_ids = {path: index for index, path in enumerate(sorted(contents))}
    contracts_by_id = {contract.ast_id: contract for contract in contracts}
    output_sources: dict[str, Any] = {}
    output_contracts: dict[str, dict[str, Any]] = {}
    occurrences: dict[tuple[str, str], int] = {}
    for path, content_text in sorted(contents.items()):
        content = content_text.encode()
        contract_nodes: list[dict[str, Any]] = []
        for contract in [item for item in contracts if item.path == path]:
            function_nodes: list[dict[str, Any]] = []
            for function in contract.functions:
                occurrence_key = (path, function.name)
                occurrence = occurrences.get(occurrence_key, 0)
                occurrences[occurrence_key] = occurrence + 1
                function_nodes.append(
                    _function_node(
                        contract=contract,
                        function=function,
                        source_id=source_ids[path],
                        content=content,
                        occurrence=occurrence,
                    )
                )
            contract_nodes.append(
                {
                    "id": contract.ast_id,
                    "nodeType": "ContractDefinition",
                    "name": contract.name,
                    "abstract": contract.abstract,
                    "contractKind": "contract",
                    "linearizedBaseContracts": list(contract.linearized),
                    "src": f"0:{len(content)}:{source_ids[path]}",
                    "nodes": function_nodes,
                }
            )
            effective = _effective_functions(contract, contracts_by_id)
            output_contracts.setdefault(path, {})[contract.name] = {
                "abi": [
                    {
                        "type": "function",
                        "name": function.name,
                        "inputs": [{"type": item} for item in function.parameter_types],
                    }
                    for _, function in sorted(effective.items())
                ]
            }
        output_sources[path] = {
            "id": source_ids[path],
            "ast": {
                "id": 10_000 + source_ids[path],
                "nodeType": "SourceUnit",
                "src": f"0:{len(content)}:{source_ids[path]}",
                "nodes": contract_nodes,
            },
        }
    payload = {
        "_format": "ethers-rs-sol-build-info-1",
        "id": "a" * 16,
        "language": "Solidity",
        "solcLongVersion": version,
        "solcVersion": version,
        "source_id_to_path": {
            str(source_id): path for path, source_id in sorted(source_ids.items())
        },
        "input": {
            "language": "Solidity",
            "sources": {path: {"content": content} for path, content in sorted(contents.items())},
            "settings": {},
            "version": version,
        },
        "output": {
            "contracts": output_contracts,
            "errors": [],
            "sources": output_sources,
        },
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _forge_list(value: dict[str, dict[str, list[str]]]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _parse(
    *,
    contents: dict[str, str],
    contracts: tuple[_ContractSpec, ...],
    forge: dict[str, dict[str, list[str]]],
    project_root: str = ".",
    build_infos: tuple[bytes, ...] | None = None,
    limits: FoundryInventoryLimits | None = None,
) -> FoundryTestInventory:
    return parse_foundry_test_inventory(
        forge_list_json=_forge_list(forge),
        build_info_jsons=build_infos or (_build_info(contents, contracts),),
        sources=_source_inputs(contents),
        project_root=project_root,
        compiler_version=_COMPILER_VERSION,
        compiler_sha256=_COMPILER_SHA256,
        limits=limits,
    )


def test_same_file_abstract_base_is_bound_to_effective_declaration() -> None:
    path = "test/SameFile.t.sol"
    contents = {
        path: (
            "abstract contract SharedBase {\n"
            "    function testInherited() public virtual {}\n"
            "}\n"
            "contract ConcreteSuite is SharedBase {}\n"
        )
    }
    contracts = (
        _ContractSpec(
            ast_id=1,
            path=path,
            name="SharedBase",
            abstract=True,
            linearized=(1,),
            functions=(_FunctionSpec(ast_id=11, name="testInherited"),),
        ),
        _ContractSpec(
            ast_id=2,
            path=path,
            name="ConcreteSuite",
            abstract=False,
            linearized=(2, 1),
        ),
    )

    inventory = _parse(
        contents=contents,
        contracts=contracts,
        forge={path: {"ConcreteSuite": ["testInherited"]}},
        project_root="packages/core",
    )

    assert inventory.project_root == "packages/core"
    assert inventory.suite_count == 1
    assert inventory.test_count == 1
    record = inventory.tests[0]
    assert record.execution_suite_name == "ConcreteSuite"
    assert record.test_name == "testInherited"
    assert record.declaration_signature == "testInherited()"
    assert record.declaration_contract == "SharedBase"
    assert record.declaration_path == path
    assert record.execution_contract_ast_id == 2
    assert record.declaration_contract_ast_id == 1
    assert record.function_ast_id == 11
    assert record.start_line == 2
    assert record.execution_start_line == 1
    assert record.source_sha256 == record.execution_source_sha256
    assert len(record.record_sha256) == 64
    assert FoundryTestInventory.model_validate(inventory.model_dump(mode="json")) == inventory


def test_imported_base_maps_to_its_own_source_hash_and_lines() -> None:
    base_path = "test/base/ImportedBase.t.sol"
    suite_path = "test/ImportedSuite.t.sol"
    contents = {
        base_path: (
            "abstract contract ImportedBase {\n"
            "\n"
            "    function invariant_ImportedRule() external virtual {}\n"
            "}\n"
        ),
        suite_path: (
            'import "./base/ImportedBase.t.sol";\ncontract ImportedSuite is ImportedBase {}\n'
        ),
    }
    contracts = (
        _ContractSpec(
            ast_id=20,
            path=base_path,
            name="ImportedBase",
            abstract=True,
            linearized=(20,),
            functions=(_FunctionSpec(ast_id=21, name="invariant_ImportedRule"),),
        ),
        _ContractSpec(
            ast_id=30,
            path=suite_path,
            name="ImportedSuite",
            abstract=False,
            linearized=(30, 20),
        ),
    )

    record = _parse(
        contents=contents,
        contracts=contracts,
        forge={suite_path: {"ImportedSuite": ["invariant_ImportedRule"]}},
    ).tests[0]

    assert record.declaration_path == base_path
    assert record.start_line == 3
    assert record.source_sha256 == hashlib.sha256(contents[base_path].encode()).hexdigest()
    assert (
        record.execution_source_sha256 == hashlib.sha256(contents[suite_path].encode()).hexdigest()
    )
    assert record.source_sha256 != record.execution_source_sha256


def test_most_derived_override_wins_linearized_resolution() -> None:
    path = "test/Override.t.sol"
    contents = {
        path: (
            "abstract contract Base {\n"
            "    function testRule() public virtual {}\n"
            "}\n"
            "contract OverrideSuite is Base {\n"
            "    function testRule() public override {}\n"
            "}\n"
        )
    }
    contracts = (
        _ContractSpec(
            ast_id=1,
            path=path,
            name="Base",
            abstract=True,
            linearized=(1,),
            functions=(_FunctionSpec(ast_id=10, name="testRule"),),
        ),
        _ContractSpec(
            ast_id=2,
            path=path,
            name="OverrideSuite",
            abstract=False,
            linearized=(2, 1),
            functions=(_FunctionSpec(ast_id=20, name="testRule"),),
        ),
    )

    record = _parse(
        contents=contents,
        contracts=contracts,
        forge={path: {"OverrideSuite": ["testRule"]}},
    ).tests[0]

    assert record.declaration_contract == "OverrideSuite"
    assert record.declaration_contract_ast_id == 2
    assert record.function_ast_id == 20
    assert record.start_line == 5


def test_diamond_inherited_test_is_inventoried_once() -> None:
    path = "test/Diamond.t.sol"
    contents = {
        path: (
            "abstract contract Root {\n"
            "    function testDiamondRule() public virtual {}\n"
            "}\n"
            "abstract contract Left is Root {}\n"
            "abstract contract Right is Root {}\n"
            "contract DiamondSuite is Left, Right {}\n"
        )
    }
    contracts = (
        _ContractSpec(
            ast_id=1,
            path=path,
            name="Root",
            abstract=True,
            linearized=(1,),
            functions=(_FunctionSpec(ast_id=10, name="testDiamondRule"),),
        ),
        _ContractSpec(
            ast_id=2,
            path=path,
            name="Left",
            abstract=True,
            linearized=(2, 1),
        ),
        _ContractSpec(
            ast_id=3,
            path=path,
            name="Right",
            abstract=True,
            linearized=(3, 1),
        ),
        _ContractSpec(
            ast_id=4,
            path=path,
            name="DiamondSuite",
            abstract=False,
            linearized=(4, 2, 3, 1),
        ),
    )

    inventory = _parse(
        contents=contents,
        contracts=contracts,
        forge={path: {"DiamondSuite": ["testDiamondRule"]}},
    )

    assert len(inventory.tests) == 1
    assert inventory.tests[0].declaration_contract == "Root"
    assert inventory.tests[0].function_ast_id == 10


def test_multiple_independent_build_units_are_reconciled_canonically() -> None:
    first_path = "test/First.t.sol"
    second_path = "test/Second.t.sol"
    contents = {
        first_path: "contract FirstSuite { function testFirst() public {} }\n",
        second_path: "contract SecondSuite { function testSecond() public {} }\n",
    }
    first_contracts = (
        _ContractSpec(
            ast_id=1,
            path=first_path,
            name="FirstSuite",
            abstract=False,
            linearized=(1,),
            functions=(_FunctionSpec(ast_id=10, name="testFirst"),),
        ),
    )
    second_contracts = (
        _ContractSpec(
            ast_id=1,
            path=second_path,
            name="SecondSuite",
            abstract=False,
            linearized=(1,),
            functions=(_FunctionSpec(ast_id=10, name="testSecond"),),
        ),
    )
    build_infos = (
        _build_info({second_path: contents[second_path]}, second_contracts),
        _build_info({first_path: contents[first_path]}, first_contracts),
    )

    inventory = _parse(
        contents=contents,
        contracts=(),
        forge={
            first_path: {"FirstSuite": ["testFirst"]},
            second_path: {"SecondSuite": ["testSecond"]},
        },
        build_infos=build_infos,
    )

    assert inventory.suite_count == 2
    assert [record.test_name for record in inventory.tests] == ["testFirst", "testSecond"]
    assert inventory.build_info_sha256s == tuple(sorted(inventory.build_info_sha256s))


def test_bare_overload_is_rejected_as_ambiguous() -> None:
    path = "test/Overload.t.sol"
    contents = {
        path: (
            "contract OverloadSuite {\n"
            "    function testFuzz(uint256 value) public {}\n"
            "    function testFuzz(address account) public {}\n"
            "}\n"
        )
    }
    contracts = (
        _ContractSpec(
            ast_id=1,
            path=path,
            name="OverloadSuite",
            abstract=False,
            linearized=(1,),
            functions=(
                _FunctionSpec(ast_id=10, name="testFuzz", parameter_types=("uint256",)),
                _FunctionSpec(ast_id=11, name="testFuzz", parameter_types=("address",)),
            ),
        ),
    )

    with pytest.raises(FoundryInventoryError, match="selector is ambiguous"):
        _parse(
            contents=contents,
            contracts=contracts,
            forge={path: {"OverloadSuite": ["testFuzz"]}},
        )


@pytest.mark.parametrize(
    ("selectors", "match"),
    [
        (["testUnknown"], "selector is unknown"),
        (["testFirst"], "omitted effective compiler tests"),
    ],
)
def test_unknown_and_missing_forge_tests_fail_closed(
    selectors: list[str],
    match: str,
) -> None:
    path = "test/Missing.t.sol"
    contents = {
        path: (
            "contract MissingSuite {\n"
            "    function testFirst() public {}\n"
            "    function testSecond() public {}\n"
            "}\n"
        )
    }
    contracts = (
        _ContractSpec(
            ast_id=1,
            path=path,
            name="MissingSuite",
            abstract=False,
            linearized=(1,),
            functions=(
                _FunctionSpec(ast_id=10, name="testFirst"),
                _FunctionSpec(ast_id=11, name="testSecond"),
            ),
        ),
    )

    with pytest.raises(FoundryInventoryError, match=match):
        _parse(
            contents=contents,
            contracts=contracts,
            forge={path: {"MissingSuite": selectors}},
        )


def test_forge_inventory_omitting_an_entire_compiler_suite_path_fails_closed() -> None:
    first_path = "test/First.t.sol"
    second_path = "test/Second.t.sol"
    contents = {
        first_path: "contract FirstSuite { function testFirst() public {} }\n",
        second_path: "contract SecondSuite { function testSecond() public {} }\n",
    }
    contracts = (
        _ContractSpec(
            ast_id=1,
            path=first_path,
            name="FirstSuite",
            abstract=False,
            linearized=(1,),
            functions=(_FunctionSpec(ast_id=10, name="testFirst"),),
        ),
        _ContractSpec(
            ast_id=2,
            path=second_path,
            name="SecondSuite",
            abstract=False,
            linearized=(2,),
            functions=(_FunctionSpec(ast_id=20, name="testSecond"),),
        ),
    )

    with pytest.raises(FoundryInventoryError, match="suite inventories differ"):
        _parse(
            contents=contents,
            contracts=contracts,
            forge={first_path: {"FirstSuite": ["testFirst"]}},
        )


def test_missing_contract_and_extra_abi_function_fail_closed() -> None:
    path = "test/Strict.t.sol"
    contents = {
        path: (
            "abstract contract Base {\n"
            "    function testRule() public virtual {}\n"
            "}\n"
            "contract StrictSuite is Base {}\n"
        )
    }
    contracts = (
        _ContractSpec(
            ast_id=1,
            path=path,
            name="Base",
            abstract=True,
            linearized=(1,),
            functions=(_FunctionSpec(ast_id=10, name="testRule"),),
        ),
        _ContractSpec(
            ast_id=2,
            path=path,
            name="StrictSuite",
            abstract=False,
            linearized=(2, 1),
        ),
    )
    valid = json.loads(_build_info(contents, contracts))
    missing_contract = json.loads(json.dumps(valid))
    del missing_contract["output"]["contracts"][path]["Base"]
    extra_function = json.loads(json.dumps(valid))
    extra_function["output"]["contracts"][path]["StrictSuite"]["abi"].append(
        {"type": "function", "name": "testGhost", "inputs": []}
    )

    with pytest.raises(FoundryInventoryError, match="contract inventories differ"):
        _parse(
            contents=contents,
            contracts=contracts,
            forge={path: {"StrictSuite": ["testRule"]}},
            build_infos=(json.dumps(missing_contract, sort_keys=True).encode(),),
        )
    with pytest.raises(FoundryInventoryError, match="ABI/AST test functions differ"):
        _parse(
            contents=contents,
            contracts=contracts,
            forge={path: {"StrictSuite": ["testRule"]}},
            build_infos=(json.dumps(extra_function, sort_keys=True).encode(),),
        )


def test_duplicate_json_keys_are_rejected_at_every_layer() -> None:
    path = "test/Duplicate.t.sol"
    contents = {path: "contract DuplicateSuite { function testRule() public {} }\n"}
    contracts = (
        _ContractSpec(
            ast_id=1,
            path=path,
            name="DuplicateSuite",
            abstract=False,
            linearized=(1,),
            functions=(_FunctionSpec(ast_id=10, name="testRule"),),
        ),
    )
    valid_build = _build_info(contents, contracts)
    duplicate_forge = (
        b'{"test/Duplicate.t.sol":{"DuplicateSuite":["testRule"]},'
        b'"test/Duplicate.t.sol":{"DuplicateSuite":["testRule"]}}'
    )
    duplicate_build = valid_build.replace(
        b'"language":"Solidity"',
        b'"language":"Solidity","language":"Solidity"',
        1,
    )

    with pytest.raises(FoundryInventoryError, match="duplicate JSON keys"):
        parse_foundry_test_inventory(
            forge_list_json=duplicate_forge,
            build_info_jsons=(valid_build,),
            sources=_source_inputs(contents),
            compiler_version=_COMPILER_VERSION,
            compiler_sha256=_COMPILER_SHA256,
        )
    with pytest.raises(FoundryInventoryError, match="duplicate JSON keys"):
        parse_foundry_test_inventory(
            forge_list_json=_forge_list({path: {"DuplicateSuite": ["testRule"]}}),
            build_info_jsons=(duplicate_build,),
            sources=_source_inputs(contents),
            compiler_version=_COMPILER_VERSION,
            compiler_sha256=_COMPILER_SHA256,
        )


def test_source_hash_content_path_and_ast_mapping_are_verified() -> None:
    path = "test/Bound.t.sol"
    contents = {path: "contract BoundSuite { function testBound() public {} }\n"}
    contracts = (
        _ContractSpec(
            ast_id=1,
            path=path,
            name="BoundSuite",
            abstract=False,
            linearized=(1,),
            functions=(_FunctionSpec(ast_id=10, name="testBound"),),
        ),
    )
    valid = json.loads(_build_info(contents, contracts))
    wrong_source_id = json.loads(json.dumps(valid))
    wrong_source_id["output"]["sources"][path]["ast"]["nodes"][0]["nodes"][0]["src"] = "0:1:999"
    wrong_content = json.loads(json.dumps(valid))
    wrong_content["input"]["sources"][path]["content"] += " "
    wrong_mapping = json.loads(json.dumps(valid))
    wrong_mapping["source_id_to_path"]["0"] = "test/Elsewhere.t.sol"
    unknown_linearized_base = json.loads(json.dumps(valid))
    unknown_linearized_base["output"]["sources"][path]["ast"]["nodes"][0][
        "linearizedBaseContracts"
    ] = [1, 999]

    invalid_hash_sources = list(_source_inputs(contents))
    invalid_hash_sources[0] = FoundrySourceInput(
        path=path,
        content=invalid_hash_sources[0].content,
        source_sha256="0" * 64,
    )
    with pytest.raises(FoundryInventoryError, match="source hash is inconsistent"):
        parse_foundry_test_inventory(
            forge_list_json=_forge_list({path: {"BoundSuite": ["testBound"]}}),
            build_info_jsons=(_build_info(contents, contracts),),
            sources=tuple(invalid_hash_sources),
            compiler_version=_COMPILER_VERSION,
            compiler_sha256=_COMPILER_SHA256,
        )
    with pytest.raises(FoundryInventoryError, match="source-unit mapping"):
        _parse(
            contents=contents,
            contracts=contracts,
            forge={path: {"BoundSuite": ["testBound"]}},
            build_infos=(json.dumps(wrong_source_id, sort_keys=True).encode(),),
        )
    with pytest.raises(FoundryInventoryError, match="content differs"):
        _parse(
            contents=contents,
            contracts=contracts,
            forge={path: {"BoundSuite": ["testBound"]}},
            build_infos=(json.dumps(wrong_content, sort_keys=True).encode(),),
        )
    with pytest.raises(FoundryInventoryError, match="source ID mapping differs"):
        _parse(
            contents=contents,
            contracts=contracts,
            forge={path: {"BoundSuite": ["testBound"]}},
            build_infos=(json.dumps(wrong_mapping, sort_keys=True).encode(),),
        )
    with pytest.raises(FoundryInventoryError, match="linearization is malformed"):
        _parse(
            contents=contents,
            contracts=contracts,
            forge={path: {"BoundSuite": ["testBound"]}},
            build_infos=(json.dumps(unknown_linearized_base, sort_keys=True).encode(),),
        )
    with pytest.raises(FoundryInventoryError, match="contained POSIX path"):
        parse_foundry_test_inventory(
            forge_list_json=_forge_list({"../Bound.t.sol": {"BoundSuite": ["testBound"]}}),
            build_info_jsons=(_build_info(contents, contracts),),
            sources=_source_inputs(contents),
            compiler_version=_COMPILER_VERSION,
            compiler_sha256=_COMPILER_SHA256,
        )


def test_duplicate_build_info_ceiling_and_self_hash_tamper_fail_closed() -> None:
    path = "test/Ceiling.t.sol"
    contents = {
        path: (
            "contract CeilingSuite {\n"
            "    function testFirst() public {}\n"
            "    function testSecond() public {}\n"
            "}\n"
        )
    }
    contracts = (
        _ContractSpec(
            ast_id=1,
            path=path,
            name="CeilingSuite",
            abstract=False,
            linearized=(1,),
            functions=(
                _FunctionSpec(ast_id=10, name="testFirst"),
                _FunctionSpec(ast_id=11, name="testSecond"),
            ),
        ),
    )
    build = _build_info(contents, contracts)
    forge = {path: {"CeilingSuite": ["testFirst", "testSecond"]}}
    with pytest.raises(FoundryInventoryError, match="duplicate content"):
        _parse(
            contents=contents,
            contracts=contracts,
            forge=forge,
            build_infos=(build, build),
        )
    with pytest.raises(FoundryInventoryError, match="test ceiling"):
        _parse(
            contents=contents,
            contracts=contracts,
            forge=forge,
            limits=FoundryInventoryLimits(max_tests=1),
        )

    inventory = _parse(contents=contents, contracts=contracts, forge=forge)
    serialized = inventory.model_dump(mode="json")
    serialized["tests"][0]["function_ast_id"] = 999
    with pytest.raises(ValidationError, match="self-hash"):
        FoundryTestInventory.model_validate(serialized)
