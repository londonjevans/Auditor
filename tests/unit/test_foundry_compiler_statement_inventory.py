from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterator
from typing import Any

import pytest

from mmaudit.scanners.foundry_inventory import (
    FoundryInventoryError,
    FoundrySourceInput,
    parse_foundry_compiler_statement_catalog,
)

_COMPILER_VERSION = "0.8.30+commit.73712a01"
_COMPILER_SHA256 = "c" * 64
_PATH = "src/Catalog.sol"
_SOURCE = (
    "é contract Catalog {\n"
    "function run() external {\n"
    "call();\n"
    "uint value = 1;\n"
    "emit Event();\n"
    "revert Failure();\n"
    "return;\n"
    "_;\n"
    "break;\n"
    "continue;\n"
    "throw;\n"
    "assembly {\n"
    "x := 1\n"
    "let y := 2\n"
    "pop(y)\n"
    "leave\n"
    "break\n"
    "continue\n"
    "}\n"
    "}\n"
    "}\n"
)
_SOLIDITY_TYPES = {
    "Break",
    "Continue",
    "EmitStatement",
    "ExpressionStatement",
    "PlaceholderStatement",
    "Return",
    "RevertStatement",
    "Throw",
    "VariableDeclarationStatement",
}
_YUL_TYPES = {
    "YulAssignment",
    "YulBreak",
    "YulContinue",
    "YulExpressionStatement",
    "YulLeave",
    "YulVariableDeclaration",
}


def _source_input() -> FoundrySourceInput:
    content = _SOURCE.encode()
    return FoundrySourceInput(
        path=_PATH,
        content=content,
        source_sha256=hashlib.sha256(content).hexdigest(),
    )


def _span(token: str, *, occurrence: int = 0) -> str:
    content = _SOURCE.encode()
    needle = token.encode()
    cursor = 0
    start = -1
    for _ in range(occurrence + 1):
        start = content.index(needle, cursor)
        cursor = start + len(needle)
    return f"{start}:{len(needle)}:0"


def _solidity_statement(ast_id: int, node_type: str, token: str) -> dict[str, Any]:
    node: dict[str, Any] = {
        "id": ast_id,
        "nodeType": node_type,
        "src": _span(token),
    }
    if node_type == "ExpressionStatement":
        node["expression"] = {
            "id": 100,
            "nodeType": "FunctionCall",
            "src": _span(token),
        }
    return node


def _build_payload(*, settings_marker: str = "one") -> dict[str, Any]:
    content = _SOURCE.encode()
    assembly_text = "assembly {\nx := 1\nlet y := 2\npop(y)\nleave\nbreak\ncontinue\n}"
    assembly_src = _span(assembly_text)
    yul_statements = [
        {
            "nodeType": "YulAssignment",
            "src": _span("x := 1"),
            "nativeSrc": _span("x := 1"),
        },
        {
            "nodeType": "YulVariableDeclaration",
            "src": _span("let y := 2"),
            "nativeSrc": _span("let y := 2"),
        },
        {
            "nodeType": "YulExpressionStatement",
            "src": _span("pop(y)"),
            "nativeSrc": _span("pop(y)"),
        },
        {
            "nodeType": "YulLeave",
            "src": _span("leave"),
            "nativeSrc": _span("leave"),
        },
        {
            "nodeType": "YulBreak",
            "src": _span("break\n"),
            "nativeSrc": _span("break\n"),
        },
        {
            "nodeType": "YulContinue",
            "src": _span("continue\n"),
            "nativeSrc": _span("continue\n"),
        },
    ]
    statements = [
        _solidity_statement(10, "ExpressionStatement", "call();"),
        _solidity_statement(11, "VariableDeclarationStatement", "uint value = 1;"),
        _solidity_statement(12, "EmitStatement", "emit Event();"),
        _solidity_statement(13, "RevertStatement", "revert Failure();"),
        _solidity_statement(14, "Return", "return;"),
        _solidity_statement(15, "PlaceholderStatement", "_;"),
        _solidity_statement(16, "Break", "break;"),
        _solidity_statement(17, "Continue", "continue;"),
        _solidity_statement(18, "Throw", "throw;"),
        {
            "AST": {
                "nativeSrc": assembly_src,
                "nodeType": "YulBlock",
                "src": assembly_src,
                "statements": yul_statements,
            },
            "id": 30,
            "nodeType": "InlineAssembly",
            "src": assembly_src,
        },
    ]
    return {
        "_format": "ethers-rs-sol-build-info-1",
        "id": "0" * 16,
        "language": "Solidity",
        "solcLongVersion": _COMPILER_VERSION,
        "solcVersion": _COMPILER_VERSION,
        "source_id_to_path": {"0": _PATH},
        "input": {
            "language": "Solidity",
            "settings": {"metadata": {"marker": settings_marker}},
            "sources": {_PATH: {"content": _SOURCE}},
            "version": _COMPILER_VERSION,
        },
        "output": {
            "errors": [],
            "sources": {
                _PATH: {
                    "ast": {
                        "id": 1,
                        "nodeType": "SourceUnit",
                        "nodes": [
                            {
                                "abstract": False,
                                "contractKind": "contract",
                                "id": 2,
                                "name": "Catalog",
                                "nodeType": "ContractDefinition",
                                "nodes": [
                                    {
                                        "body": {
                                            "id": 4,
                                            "nodeType": "Block",
                                            "src": f"0:{len(content)}:0",
                                            "statements": statements,
                                        },
                                        "id": 3,
                                        "kind": "function",
                                        "name": "run",
                                        "nodeType": "FunctionDefinition",
                                        "scope": 2,
                                        "src": f"0:{len(content)}:0",
                                    }
                                ],
                                "src": f"0:{len(content)}:0",
                            }
                        ],
                        "src": f"0:{len(content)}:0",
                    },
                    "id": 0,
                }
            },
        },
    }


def _encoded(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _nodes(value: object) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        if "nodeType" in value:
            yield value
        for child in value.values():
            yield from _nodes(child)
    elif isinstance(value, list):
        for child in value:
            yield from _nodes(child)


def _parse(*payloads: dict[str, Any]):
    return parse_foundry_compiler_statement_catalog(
        build_info_jsons=tuple(_encoded(payload) for payload in payloads),
        sources=(_source_input(),),
        project_root="packages/core",
        compiler_version=_COMPILER_VERSION,
        compiler_sha256=_COMPILER_SHA256,
    )


def test_catalog_exposes_exact_sources_entities_and_atomic_statement_leaves() -> None:
    raw = _encoded(_build_payload())
    catalog = parse_foundry_compiler_statement_catalog(
        build_info_jsons=(raw,),
        sources=(_source_input(),),
        project_root="packages/core",
        compiler_version=_COMPILER_VERSION,
        compiler_sha256=_COMPILER_SHA256,
    )

    assert catalog.project_root == "packages/core"
    assert catalog.compiler_version == _COMPILER_VERSION
    assert catalog.compiler_sha256 == _COMPILER_SHA256
    assert len(catalog.units) == 1
    unit = catalog.units[0]
    assert unit.project_root == catalog.project_root
    assert unit.normalized_build_info_sha256 == hashlib.sha256(raw).hexdigest()
    assert unit.source_id_to_path == ((0, _PATH),)
    assert len(unit.sources) == 1
    assert unit.sources[0].content == _SOURCE.encode()
    assert unit.sources[0].source_sha256 == hashlib.sha256(_SOURCE.encode()).hexdigest()
    assert [(entity.node_type, entity.kind, entity.name) for entity in unit.entities] == [
        ("ContractDefinition", "contract", "Catalog"),
        ("FunctionDefinition", "function", "run"),
    ]
    assert {statement.node_type for statement in unit.statements} == (_SOLIDITY_TYPES | _YUL_TYPES)
    assert "FunctionCall" not in {statement.node_type for statement in unit.statements}
    assert "Block" not in {statement.node_type for statement in unit.statements}
    for previous, current in zip(unit.statements, unit.statements[1:], strict=False):
        assert previous.path != current.path or previous.end_byte_exclusive <= current.start_byte
    solidity = [item for item in unit.statements if item.node_type in _SOLIDITY_TYPES]
    yul = [item for item in unit.statements if item.node_type in _YUL_TYPES]
    assert all(
        item.compiler_ast_id is not None
        and item.enclosing_inline_assembly_ast_id is None
        and item.enclosing_contract_ast_id == 2
        and item.enclosing_function_ast_id == 3
        for item in solidity
    )
    assert all(
        item.compiler_ast_id is None
        and item.enclosing_inline_assembly_ast_id == 30
        and item.enclosing_contract_ast_id == 2
        and item.enclosing_function_ast_id == 3
        for item in yul
    )
    expression = next(item for item in unit.statements if item.node_type == "ExpressionStatement")
    assert _SOURCE.encode()[expression.start_byte : expression.end_byte_exclusive] == b"call();"
    assert (expression.start_line, expression.end_line_exclusive) == (3, 4)


def test_semantically_repeated_build_units_are_retained_when_equivalent() -> None:
    first = _build_payload(settings_marker="one")
    second = _build_payload(settings_marker="two")

    catalog = _parse(first, second)

    assert len(catalog.units) == 2
    assert tuple(unit.normalized_build_info_sha256 for unit in catalog.units) == tuple(
        sorted(unit.normalized_build_info_sha256 for unit in catalog.units)
    )


def test_semantically_repeated_build_units_reject_statement_conflicts() -> None:
    first = _build_payload(settings_marker="one")
    second = _build_payload(settings_marker="two")
    expression = next(
        node for node in _nodes(second) if node.get("nodeType") == "ExpressionStatement"
    )
    expression["nodeType"] = "Return"

    with pytest.raises(FoundryInventoryError, match="conflicts across build units"):
        _parse(first, second)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("duplicate_id", "AST ID is duplicated"),
        ("unknown_source", "unknown source ID"),
        ("utf8_boundary", "UTF-8 boundaries"),
        ("whitespace", "whitespace-only"),
        ("overlap", "atomic statements overlap"),
        ("yul_id", "Yul AST node unexpectedly carries an ID"),
    ],
)
def test_catalog_rejects_untrustworthy_ast_statement_identity(
    mutation: str,
    message: str,
) -> None:
    payload = copy.deepcopy(_build_payload())
    nodes = list(_nodes(payload))
    expression = next(node for node in nodes if node.get("nodeType") == "ExpressionStatement")
    variable = next(
        node for node in nodes if node.get("nodeType") == "VariableDeclarationStatement"
    )
    yul = next(node for node in nodes if node.get("nodeType") == "YulAssignment")
    if mutation == "duplicate_id":
        variable["id"] = expression["id"]
    elif mutation == "unknown_source":
        expression["src"] = expression["src"].rsplit(":", maxsplit=1)[0] + ":7"
    elif mutation == "utf8_boundary":
        expression["src"] = "1:1:0"
    elif mutation == "whitespace":
        whitespace_start = _SOURCE.encode().index(b" ")
        expression["src"] = f"{whitespace_start}:1:0"
    elif mutation == "overlap":
        variable["src"] = expression["src"]
    else:
        yul["id"] = 999

    with pytest.raises(FoundryInventoryError, match=message):
        _parse(payload)


def test_catalog_requires_normalized_build_info_identity() -> None:
    payload = _build_payload()
    payload["id"] = "a" * 16

    with pytest.raises(FoundryInventoryError, match="identifier is not normalized"):
        _parse(payload)
