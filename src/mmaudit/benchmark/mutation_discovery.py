"""Pure compiler/source-bound mutation discovery, without applicability or runtime credit.

The existing compiler inventory parser validates supplied build-info and source
bytes. This layer resolves declarations and statement relationships, then derives
the existing bounded source operations. It does not authenticate a compiler run.
"""

from __future__ import annotations

import hashlib
import json
import re
from bisect import bisect_left, bisect_right
from collections.abc import Mapping
from dataclasses import dataclass
from itertools import pairwise
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from mmaudit.benchmark.mutation_portfolio import (
    PortfolioSourceMutationSpec,
    SecurityMutationClass,
    _duration,
    _line_parts,
    _scale,
)
from mmaudit.models.schemas import StrictModel
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.scanners.foundry_inventory import (
    FoundryCompilerBuildUnit,
    FoundryInventoryLimits,
    FoundryInventorySourceBinding,
    FoundrySourceInput,
    _ast_child_nodes,
    compiler_catalog_source_bindings,
    parse_foundry_compiler_statement_catalog,
)
from mmaudit.scanners.foundry_inventory import (
    _canonical_sha256 as canonical_sha256,
)
from mmaudit.solidity.compiler_source import CompilerSourceMap
from mmaudit.solidity.invariants import _mask_solidity_comments_and_strings

_SHA = r"^[0-9a-f]{64}$"
_ATOMIC = {"ExpressionStatement", "Return", "VariableDeclarationStatement"}
_EXPRESSION_CHILDREN = {
    "ExpressionStatement": ("expression",),
    "BinaryOperation": ("leftExpression", "rightExpression"),
    "Assignment": ("leftHandSide", "rightHandSide"),
    "UnaryOperation": ("subExpression",),
    "FunctionCall": ("expression",),
    "MemberAccess": ("expression",),
    "IndexAccess": ("baseExpression",),
}
_GAP = "No supported candidate; this is not proof of class absence or non-applicability."
_LIMITATIONS = (
    "Supplied compiler/source consistency is not independent compiler-execution custody.",
    "Structural candidates are not proven property applicability or exhaustive semantic coverage.",
    "Unsupported syntax and absent classes remain gaps; no mutation execution is credited.",
)


class PortfolioDiscoveryLimits(StrictModel):
    maximum_candidates: int = Field(default=10_000, ge=1, le=100_000)
    maximum_unsupported: int = Field(default=10_000, ge=1, le=100_000)


class DiscoveredPortfolioMutation(StrictModel):
    specification: PortfolioSourceMutationSpec
    build_info_sha256: str = Field(pattern=_SHA)
    source_id: int = Field(ge=0)
    ast_node_ids: tuple[int, ...] = Field(min_length=1, max_length=32)
    declaration_ast_ids: tuple[int, ...] = Field(max_length=100)
    start_byte: int = Field(ge=0)
    end_byte_exclusive: int = Field(gt=0)

    @model_validator(mode="after")
    def exact_candidate_identity(self) -> Self:
        if self.end_byte_exclusive <= self.start_byte:
            raise ValueError("mutation discovery span is empty or reversed")
        for ids in (self.ast_node_ids, self.declaration_ast_ids):
            if ids != tuple(sorted(set(ids))) or any(type(i) is not int or i < 0 for i in ids):
                raise ValueError("discovery AST identities must be unique nonnegative integers")
        identity = self.model_dump(mode="json")
        identity["specification"].pop("id")
        if self.specification.id != "mut-" + canonical_sha256(identity):
            raise ValueError("discovered mutation identity differs from compiler/source evidence")
        return self


class UnsupportedPortfolioMutation(StrictModel):
    id: str = Field(pattern=_SHA)
    kind: SecurityMutationClass
    path: str
    build_info_sha256: str = Field(pattern=_SHA)
    ast_node_id: int = Field(ge=0)
    reason: Literal["SEMANTIC_CONTEXT_NOT_ESTABLISHED", "UNSUPPORTED_SOURCE_SHAPE"]


class PortfolioSourceClassCoverage(StrictModel):
    path: str
    kind: SecurityMutationClass
    candidate_ids: tuple[str, ...]
    unsupported_ids: tuple[str, ...]
    limitation: str | None = None


class PortfolioMutationDiscovery(StrictModel):
    """A complete selected-source/class denominator, never a qualification artifact."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["portfolio_mutation_discovery"] = "portfolio_mutation_discovery"
    project_root: str
    compiler_version: str = Field(min_length=1, max_length=1_000)
    compiler_sha256: str = Field(pattern=_SHA)
    build_info_sha256s: tuple[Annotated[str, Field(pattern=_SHA)], ...] = Field(
        min_length=1, max_length=1_000
    )
    sources: tuple[FoundryInventorySourceBinding, ...] = Field(min_length=1, max_length=100_000)
    target_paths: tuple[str, ...] = Field(min_length=1, max_length=100_000)
    candidates: tuple[DiscoveredPortfolioMutation, ...] = Field(max_length=100_000)
    unsupported: tuple[UnsupportedPortfolioMutation, ...] = Field(max_length=100_000)
    source_classes: tuple[PortfolioSourceClassCoverage, ...] = Field(
        min_length=11, max_length=1_100_000
    )
    limits: PortfolioDiscoveryLimits
    limitations: tuple[str, ...] = _LIMITATIONS
    property_applicability_established: Literal[False] = False
    execution_validated: Literal[False] = False
    qualification_eligible: Literal[False] = False
    discovery_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def complete_bound_discovery(self) -> Self:
        source_map = {s.path: s for s in self.sources}
        for source in self.sources:
            source.validate_builds(self.build_info_sha256s)
        if normalize_relative_path(self.project_root) != self.project_root:
            raise ValueError("discovery project root is not canonical")
        if any(
            normalize_relative_path(path) != path
            or not PurePosixPath(path).is_relative_to(PurePosixPath(self.project_root))
            for path in source_map
        ):
            raise ValueError("discovery source paths differ from its project scope")
        if tuple(source_map) != tuple(sorted(source_map)) or len(source_map) != len(self.sources):
            raise ValueError("discovery sources must be canonical and unique")
        if (
            self.target_paths != tuple(sorted(set(self.target_paths)))
            or not set(self.target_paths) <= source_map.keys()
            or self.build_info_sha256s != tuple(sorted(set(self.build_info_sha256s)))
            or self.limitations != _LIMITATIONS
        ):
            raise ValueError("discovery scope or limitations differ")
        candidate_ids = tuple(c.specification.id for c in self.candidates)
        unsupported_ids = tuple(c.id for c in self.unsupported)
        if (
            candidate_ids != tuple(sorted(set(candidate_ids)))
            or unsupported_ids != tuple(sorted(set(unsupported_ids)))
            or len(candidate_ids) > self.limits.maximum_candidates
            or len(unsupported_ids) > self.limits.maximum_unsupported
        ):
            raise ValueError("discovery candidates must be complete, unique and bounded")
        for candidate in self.candidates:
            spec = candidate.specification
            if (
                spec.path not in self.target_paths
                or candidate.build_info_sha256 not in self.build_info_sha256s
                or spec.expected_file_sha256 != source_map[spec.path].source_sha256
                or candidate.end_byte_exclusive > source_map[spec.path].size_bytes
                or any(
                    b.source_id != candidate.source_id
                    for b in source_map[spec.path].compiler_source_bindings
                    if b.build_info_sha256 == candidate.build_info_sha256
                )
            ):
                raise ValueError("candidate differs from selected compiler/source scope")
        for item in self.unsupported:
            if (
                item.path not in self.target_paths
                or item.build_info_sha256 not in self.build_info_sha256s
                or item.id != canonical_sha256(item.model_dump(mode="json", exclude={"id"}))
            ):
                raise ValueError("unsupported candidate identity differs")
        expected = _coverage(self.target_paths, self.candidates, self.unsupported)
        if self.source_classes != expected:
            raise ValueError("every selected source/class candidate and gap must remain visible")
        if self.discovery_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"discovery_sha256"})
        ):
            raise ValueError("mutation discovery digest differs")
        return self


def _coverage(
    targets: tuple[str, ...],
    candidates: tuple[DiscoveredPortfolioMutation, ...],
    unsupported: tuple[UnsupportedPortfolioMutation, ...],
) -> tuple[PortfolioSourceClassCoverage, ...]:
    candidate_map: dict[tuple[str, SecurityMutationClass], list[str]] = {}
    unsupported_map: dict[tuple[str, SecurityMutationClass], list[str]] = {}
    for item in candidates:
        spec = item.specification
        candidate_map.setdefault((spec.path, spec.kind), []).append(spec.id)
    for rejected in unsupported:
        unsupported_map.setdefault((rejected.path, rejected.kind), []).append(rejected.id)
    return tuple(
        PortfolioSourceClassCoverage(
            path=path,
            kind=kind,
            candidate_ids=tuple(sorted(candidate_map.get((path, kind), []))),
            unsupported_ids=tuple(sorted(unsupported_map.get((path, kind), []))),
            limitation=None if candidate_map.get((path, kind)) else _GAP,
        )
        for path in targets
        for kind in SecurityMutationClass
    )


@dataclass(frozen=True)
class _Node:
    value: Mapping[str, Any]
    path: str
    start: int
    end: int
    source_id: int
    parent: int | None

    @property
    def id(self) -> int:
        return int(self.value["id"])

    @property
    def kind(self) -> str:
        return str(self.value["nodeType"])


def _nodes(
    payload: dict[str, Any], source_maps: Mapping[str, CompilerSourceMap] | None = None
) -> dict[int, _Node]:
    """Retain raw compiler nodes while exposing explicitly mapped original spans."""
    result = {}
    for path, source in sorted(payload["output"]["sources"].items()):
        pending: list[tuple[Mapping[str, Any], int | None]] = [(source["ast"], None)]
        while pending:
            value, parent = pending.pop()
            if value["nodeType"].startswith("Yul"):
                continue  # Already inventoried by the strict parser; not a Solidity operation.
            for field in _EXPRESSION_CHILDREN.get(value["nodeType"], ()):
                child = value.get(field)
                if not isinstance(child, dict) or "nodeType" not in child:
                    raise ValueError("mutation discovery AST expression shape is malformed")
            start, length, source_id = map(int, value["src"].split(":"))
            end = start + length
            if source_maps is not None and path in source_maps:
                start, end = source_maps[path].original_span(start, end)
            node = _Node(value, path, start, end, source_id, parent)
            result[node.id] = node
            pending.extend((child, node.id) for child in _ast_child_nodes(value))
    return result


def _reference(value: Any, nodes: dict[int, _Node]) -> _Node | None:
    if not isinstance(value, dict):
        return None
    reference = value.get("referencedDeclaration")
    result = nodes.get(reference) if type(reference) is int else None
    if result is not None:
        name = value.get("name", value.get("memberName"))
        if name is not None and name != result.value.get("name"):
            return None
    return result


def _state(value: Any, nodes: dict[int, _Node]) -> _Node | None:
    for _ in range(64):
        if not isinstance(value, dict):
            return None
        if value.get("nodeType") == "Identifier":
            declaration = _reference(value, nodes)
            if declaration is None:
                return None
            parent = nodes.get(declaration.parent) if declaration.parent is not None else None
            return (
                declaration
                if (
                    declaration.kind == "VariableDeclaration"
                    and declaration.value.get("stateVariable") is True
                    and parent is not None
                    and parent.kind == "ContractDefinition"
                    and declaration.value.get("scope") == parent.id
                )
                else None
            )
        if value.get("nodeType") == "IndexAccess":
            value = value.get("baseExpression")
        elif value.get("nodeType") == "MemberAccess":
            value = value.get("expression")
        else:
            return None
    return None


def _builtin_member(value: Any, base: str, member: str) -> bool:
    if not isinstance(value, dict) or value.get("nodeType") != "MemberAccess":
        return False
    expression = value.get("expression", {})
    declaration = expression.get("referencedDeclaration")
    return (
        value.get("memberName") == member
        and expression.get("nodeType") == "Identifier"
        and expression.get("name") == base
        and type(declaration) is int
        and declaration < 0
    )


def _walk(value: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    pending = [value]
    while pending:
        current = pending.pop()
        result.append(current)
        pending.extend(_ast_child_nodes(current))
    return result


def _condition(node: _Node) -> dict[str, Any] | None:
    expression = node.value.get("expression", {})
    callee = expression.get("expression", {})
    arguments = expression.get("arguments", [])
    builtin_type = callee.get("typeDescriptions", {}).get("typeIdentifier", "")
    if (
        node.kind == "ExpressionStatement"
        and expression.get("nodeType") == "FunctionCall"
        and callee.get("nodeType") == "Identifier"
        and callee.get("name") == "require"
        and isinstance(builtin_type, str)
        and builtin_type.startswith("t_function_require_")
        and arguments
    ):
        return arguments[0] if isinstance(arguments[0], dict) else None
    return None


def _external_call(value: Any, nodes: dict[int, _Node]) -> _Node | None:
    if not isinstance(value, dict) or value.get("nodeType") != "FunctionCall":
        return None
    callee = value.get("expression", {})
    declaration = _reference(callee, nodes)
    function_type = callee.get("typeDescriptions", {}).get("typeIdentifier", "")
    if declaration is None or declaration.parent is None:
        return None
    parent = nodes[declaration.parent]
    if (
        callee.get("nodeType") == "MemberAccess"
        and declaration.kind == "FunctionDefinition"
        and declaration.value.get("visibility") in {"external", "public"}
        and parent.kind == "ContractDefinition"
        and parent.value.get("contractKind") != "library"
        and isinstance(function_type, str)
        and function_type.startswith("t_function_external_")
    ):
        return declaration
    return None


def _atomic(node: _Node, nodes: dict[int, _Node]) -> _Node | None:
    for _ in range(128):
        if node.kind in _ATOMIC:
            return node
        if node.parent is None or node.kind in {"FunctionDefinition", "ContractDefinition"}:
            return None
        node = nodes[node.parent]
    return None


@dataclass(frozen=True)
class _SourceLines:
    source: FoundrySourceInput
    offsets: tuple[int, ...]
    bodies: tuple[str, ...]
    masked_bodies: tuple[str, ...]

    @classmethod
    def build(cls, source: FoundrySourceInput) -> _SourceLines:
        text = source.content.decode("utf-8")
        masked = _mask_solidity_comments_and_strings(text)
        offsets = [0]
        bodies = []
        masked_bodies = []
        character_offset = 0
        for line in text.splitlines(keepends=True):
            body, _ = _line_parts(line)
            bodies.append(body)
            masked_bodies.append(masked[character_offset : character_offset + len(body)])
            character_offset += len(line)
            offsets.append(offsets[-1] + len(line.encode()))
        return cls(source, tuple(offsets), tuple(bodies), tuple(masked_bodies))


@dataclass
class _Discovery:
    unit: FoundryCompilerBuildUnit
    nodes: dict[int, _Node]
    limits: PortfolioDiscoveryLimits
    candidates: dict[str, DiscoveredPortfolioMutation]
    unsupported: dict[str, UnsupportedPortfolioMutation]
    source_lines: dict[str, _SourceLines]

    def path(self, node: _Node) -> str:
        return str(PurePosixPath(self.unit.project_root, node.path))

    def reject(self, kind: SecurityMutationClass, node: _Node, *, semantic: bool = True) -> None:
        values: dict[str, Any] = dict(
            kind=kind,
            path=self.path(node),
            build_info_sha256=self.unit.normalized_build_info_sha256,
            ast_node_id=node.id,
            reason="SEMANTIC_CONTEXT_NOT_ESTABLISHED" if semantic else "UNSUPPORTED_SOURCE_SHAPE",
        )
        item = UnsupportedPortfolioMutation(id=canonical_sha256(values), **values)
        self.unsupported[item.id] = item
        if len(self.unsupported) > self.limits.maximum_unsupported:
            raise ValueError("mutation discovery unsupported inventory exceeds its bound")

    def text(self, node: _Node) -> str:
        source = self.source_lines[node.path].source
        return source.content[node.start : node.end].decode("utf-8")

    def offer(
        self,
        kind: SecurityMutationClass,
        node: _Node,
        *,
        end: _Node | None = None,
        declarations: tuple[int, ...] = (),
        tokens: tuple[str, str] | None = None,
        end_byte: int | None = None,
    ) -> None:
        indexed = self.source_lines[node.path]
        source = indexed.source
        finish = end_byte if end_byte is not None else (end.end if end else node.end)
        first = bisect_right(indexed.offsets, node.start) - 1
        last = bisect_left(indexed.offsets, finish) - 1
        if not 0 <= first <= last < len(indexed.bodies) or last - first >= 32:
            self.reject(kind, node, semantic=False)
            return
        prefix_length = len(source.content[indexed.offsets[first] : node.start].decode())
        end_column = len(source.content[indexed.offsets[last] : finish].decode())
        expected_lines = indexed.bodies[first : last + 1]
        if (
            indexed.masked_bodies[first][:prefix_length].strip()
            or indexed.masked_bodies[last][end_column:].strip() not in {"", ";"}
            or "\n".join(indexed.masked_bodies[first : last + 1])
            != _mask_solidity_comments_and_strings("\n".join(expected_lines))
        ):
            self.reject(kind, node, semantic=False)
            return
        try:
            spec = PortfolioSourceMutationSpec(
                id="mut-pending",
                kind=kind,
                path=self.path(node),
                line=first + 1,
                expected_file_sha256=source.source_sha256,
                expected_lines=expected_lines,
                original_token=tokens[0] if tokens else None,
                replacement_token=tokens[1] if tokens else None,
            )
        except ValueError:
            self.reject(kind, node, semantic=False)
            return
        values: dict[str, Any] = dict(
            specification=spec,
            build_info_sha256=self.unit.normalized_build_info_sha256,
            source_id=node.source_id,
            ast_node_ids=tuple(sorted({node.id, end.id if end else node.id})),
            declaration_ast_ids=tuple(sorted(set(declarations))),
            start_byte=node.start,
            end_byte_exclusive=finish,
        )
        provisional = DiscoveredPortfolioMutation.model_construct(**values)
        identity = provisional.model_dump(mode="json")
        identity["specification"].pop("id")
        spec = PortfolioSourceMutationSpec.model_validate(
            {**spec.model_dump(), "id": "mut-" + canonical_sha256(identity)}
        )
        item = DiscoveredPortfolioMutation(**{**values, "specification": spec})
        self.candidates[spec.id] = item
        if len(self.candidates) > self.limits.maximum_candidates:
            raise ValueError("mutation discovery candidate inventory exceeds its bound")

    def guards(self, node: _Node, condition: dict[str, Any]) -> None:
        kind = SecurityMutationClass
        children = _walk(condition)
        if any(_builtin_member(child, "msg", "sender") for child in children):
            self.offer(kind.AUTHORIZATION_REMOVAL, node)
        for name, category in (
            ("initialized", kind.INITIALIZER_PROTECTION_REMOVAL),
            ("paused", kind.PAUSE_ENFORCEMENT_REMOVAL),
        ):
            identifiers = [c for c in children if c.get("name", "").lstrip("_") == name]
            if identifiers:
                declaration = _state(identifiers[0], self.nodes)
                if declaration is None:
                    self.reject(category, node)
                else:
                    self.offer(category, node, declarations=(declaration.id,))
        timestamp = any(_builtin_member(c, "block", "timestamp") for c in children)
        if timestamp:
            operator = condition.get("operator")
            left, right = condition.get("leftExpression", {}), condition.get("rightExpression", {})
            if operator in {"<", "<=", ">", ">="}:
                if _builtin_member(left, "block", "timestamp") and operator in {">", ">="}:
                    literal = right.get("rightExpression", {})
                    literal_node = self.nodes.get(literal.get("id"))
                    if right.get("operator") == "+" and literal_node is not None:
                        token = self.text(literal_node)
                        try:
                            duration = _duration(token)
                        except ValueError:
                            duration = 0
                        if duration:
                            self.offer(kind.TIMELOCK_WEAKENING, node, tokens=(token, "0"))
                        else:
                            self.reject(kind.TIMELOCK_WEAKENING, node)
                    else:
                        self.reject(kind.TIMELOCK_WEAKENING, node)
                else:
                    self.offer(kind.STALE_PRICE_VALIDATION_REMOVAL, node)

    def block(self, node: _Node) -> None:
        statements = [
            self.nodes[s["id"]]
            for s in node.value.get("statements", [])
            if s.get("id") in self.nodes
        ]
        for first, second in pairwise(statements):
            assignment = first.value.get("expression", {})
            call = second.value.get("expression", {})
            if (
                first.kind == second.kind == "ExpressionStatement"
                and assignment.get("nodeType") == "Assignment"
                and assignment.get("operator") == "="
                and call.get("nodeType") == "FunctionCall"
                and call.get("expression", {}).get("nodeType") == "MemberAccess"
            ):
                state = _state(assignment.get("leftHandSide"), self.nodes)
                target = _external_call(call, self.nodes)
                category = SecurityMutationClass.EXTERNAL_CALL_BEFORE_STATE_UPDATE
                if state and target:
                    self.offer(category, first, end=second, declarations=(state.id, target.id))
                else:
                    self.reject(category, first)
            condition = _condition(second)
            if condition is not None and condition.get("nodeType") == "Identifier":
                declaration = _reference(condition, self.nodes)
                if declaration is None or declaration.value.get("name") not in {
                    "ok",
                    "success",
                    "succeeded",
                }:
                    continue
                declarations = first.value.get("declarations", [])
                target = _external_call(first.value.get("initialValue"), self.nodes)
                category = SecurityMutationClass.UNCHECKED_RETURN_HANDLING
                if (
                    first.kind == "VariableDeclarationStatement"
                    and len(declarations) == 1
                    and declarations[0].get("id") == declaration.id
                    and target is not None
                    and declaration.value.get("typeDescriptions", {}).get("typeString") == "bool"
                ):
                    self.offer(category, second, declarations=(declaration.id, target.id))
                else:
                    self.reject(category, second)

    def node(self, node: _Node) -> None:
        category = SecurityMutationClass
        condition = _condition(node)
        if condition is not None:
            self.guards(node, condition)
        if node.kind in {"Block", "UncheckedBlock"}:
            self.block(node)
        if node.kind == "ExpressionStatement":
            value = node.value.get("expression", {})
            target = value.get("leftHandSide", value.get("subExpression"))
            referenced = _reference(target, self.nodes)
            state = _state(target, self.nodes)
            selected_declaration = state or referenced
            name = selected_declaration.value.get("name", "") if selected_declaration else ""
            if re.match(r"_?(?:nonces?|used|consumed|executed|processed)", name, re.I):
                if state:
                    self.offer(category.NONCE_UPDATE_REMOVAL, node, declarations=(state.id,))
                else:
                    self.reject(category.NONCE_UPDATE_REMOVAL, node)
        if node.kind == "MemberAccess" and node.value.get("memberName") in {
            "Floor",
            "Ceil",
            "Down",
            "Up",
        }:
            declaration = _reference(node.value, self.nodes)
            enum = (
                self.nodes.get(declaration.parent)
                if declaration and declaration.parent is not None
                else None
            )
            selected = _atomic(node, self.nodes)
            if selected is not None:
                original = str(node.value["memberName"])
                replacement = {"Floor": "Ceil", "Ceil": "Floor", "Down": "Up", "Up": "Down"}[
                    original
                ]
                members = (
                    {member.get("name") for member in enum.value.get("members", [])}
                    if enum
                    else set()
                )
                if (
                    declaration
                    and declaration.kind == "EnumValue"
                    and enum
                    and enum.kind == "EnumDefinition"
                    and enum.value.get("name") == "Rounding"
                    and replacement in members
                ):
                    self.offer(
                        category.ROUNDING_DIRECTION,
                        selected,
                        declarations=(declaration.id, enum.id),
                        tokens=(original, replacement),
                    )
                else:
                    self.reject(category.ROUNDING_DIRECTION, node)
        if node.kind == "VariableDeclaration" and "slot" in node.value.get("name", "").lower():
            literal = self.nodes.get(node.value.get("value", {}).get("id"))
            parent = self.nodes.get(node.parent) if node.parent is not None else None
            if literal is not None:
                token = self.text(literal)
                if (
                    node.value.get("constant") is True
                    and parent
                    and parent.kind == "ContractDefinition"
                    and node.value.get("stateVariable") is True
                    and node.value.get("typeDescriptions", {}).get("typeString") == "bytes32"
                    and re.fullmatch(r"0x[0-9a-fA-F]{64}", token)
                ):
                    self.offer(
                        category.STORAGE_SLOT_CHANGE,
                        node,
                        declarations=(node.id,),
                        tokens=(token, f"0x{int(token, 16) ^ 1:064x}"),
                    )
                else:
                    self.reject(category.STORAGE_SLOT_CHANGE, node)
        if node.kind == "BinaryOperation" and node.value.get("operator") in {"*", "/"}:
            statement = _atomic(node, self.nodes)
            if statement:
                for field in ("leftExpression", "rightExpression"):
                    child = self.nodes.get(node.value.get(field, {}).get("id"))
                    if child is None or child.kind not in {"Literal", "BinaryOperation"}:
                        continue
                    token = self.text(child)
                    try:
                        exponent = _scale(token)
                    except ValueError:
                        continue
                    if exponent > 0:
                        self.offer(
                            category.INCORRECT_DECIMAL_SCALE,
                            statement,
                            tokens=(token, f"1e{exponent - 1}"),
                        )
        if node.kind == "FunctionDefinition":
            body = self.nodes.get(node.value.get("body", {}).get("id"))
            for modifier in node.value.get("modifiers", []):
                name = modifier.get("modifierName", {})
                label = name.get("name")
                if label not in {"initializer", "whenNotPaused"} or body is None:
                    continue
                kind = (
                    category.INITIALIZER_PROTECTION_REMOVAL
                    if label == "initializer"
                    else category.PAUSE_ENFORCEMENT_REMOVAL
                )
                declaration = _reference(name, self.nodes)
                if declaration is None or declaration.kind != "ModifierDefinition":
                    self.reject(kind, node)
                else:
                    self.offer(kind, node, end_byte=body.start + 1, declarations=(declaration.id,))


def discover_portfolio_mutations(
    *,
    build_info_jsons: tuple[bytes, ...],
    sources: tuple[FoundrySourceInput, ...],
    target_paths: tuple[str, ...],
    compiler_version: str,
    compiler_sha256: str,
    project_root: str = ".",
    inventory_limits: FoundryInventoryLimits | None = None,
    limits: PortfolioDiscoveryLimits | None = None,
) -> PortfolioMutationDiscovery:
    """Derive exact operations automatically from immutable supplied compiler/source evidence.

    Targets are explicit project-relative source inventory members, never manually
    selected mutation lines. No files, commands, models or external services are used.
    """

    if (
        type(build_info_jsons) is not tuple
        or any(type(raw) is not bytes for raw in build_info_jsons)
        or type(sources) is not tuple
        or any(type(s) is not FoundrySourceInput for s in sources)
        or type(target_paths) is not tuple
        or not target_paths
        or any(type(path) is not str for path in target_paths)
        or target_paths != tuple(sorted(set(target_paths)))
    ):
        raise ValueError("discovery requires immutable complete canonical input populations")
    if limits is not None and type(limits) is not PortfolioDiscoveryLimits:
        raise ValueError("mutation discovery requires exact limits")
    if inventory_limits is not None and type(inventory_limits) is not FoundryInventoryLimits:
        raise ValueError("mutation discovery requires exact compiler inventory limits")
    bounds = PortfolioDiscoveryLimits.model_validate(
        (limits or PortfolioDiscoveryLimits()).model_dump()
    )
    parser_bounds = FoundryInventoryLimits.model_validate(
        (inventory_limits or FoundryInventoryLimits()).model_dump()
    )
    catalog = parse_foundry_compiler_statement_catalog(
        build_info_jsons=build_info_jsons,
        sources=sources,
        project_root=project_root,
        compiler_version=compiler_version,
        compiler_sha256=compiler_sha256,
        limits=parser_bounds,
    )
    if not set(target_paths) <= {s.path for s in sources} or any(
        normalize_relative_path(path) != path or PurePosixPath(path).suffix != ".sol"
        for path in target_paths
    ):
        raise ValueError("mutation targets differ from the exact supplied Solidity inventory")
    payloads = {hashlib.sha256(raw).hexdigest(): json.loads(raw) for raw in build_info_jsons}
    candidates: dict[str, DiscoveredPortfolioMutation] = {}
    unsupported: dict[str, UnsupportedPortfolioMutation] = {}
    source_lines = {source.path: _SourceLines.build(source) for source in sources}
    for unit in catalog.units:
        nodes = _nodes(
            payloads[unit.normalized_build_info_sha256],
            {s.path: s.source_mapping for s in unit.sources if s.source_mapping is not None},
        )
        discovery = _Discovery(unit, nodes, bounds, candidates, unsupported, source_lines)
        for node in sorted(nodes.values(), key=lambda n: (n.path, n.start, n.end, n.id)):
            if node.path in target_paths:
                try:
                    discovery.node(node)
                except (AttributeError, KeyError, TypeError, IndexError) as exc:
                    raise ValueError("mutation discovery AST shape is malformed") from exc
    ordered_candidates = tuple(candidates[key] for key in sorted(candidates))
    ordered_unsupported = tuple(unsupported[key] for key in sorted(unsupported))
    targets = tuple(sorted(str(PurePosixPath(catalog.project_root, path)) for path in target_paths))
    values: dict[str, Any] = dict(
        project_root=catalog.project_root,
        compiler_version=catalog.compiler_version,
        compiler_sha256=catalog.compiler_sha256,
        build_info_sha256s=tuple(unit.normalized_build_info_sha256 for unit in catalog.units),
        sources=tuple(
            s.model_copy(
                update={"path": str(PurePosixPath(catalog.project_root, s.path))},
            )
            for s in compiler_catalog_source_bindings(catalog)
        ),
        target_paths=targets,
        candidates=ordered_candidates,
        unsupported=ordered_unsupported,
        source_classes=_coverage(targets, ordered_candidates, ordered_unsupported),
        limits=bounds,
    )
    provisional = PortfolioMutationDiscovery.model_construct(**values, discovery_sha256="0" * 64)
    return PortfolioMutationDiscovery.model_validate(
        {
            **provisional.model_dump(),
            "discovery_sha256": canonical_sha256(
                provisional.model_dump(mode="json", exclude={"discovery_sha256"})
            ),
        }
    )
