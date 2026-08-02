"""Solidity AST extraction and source symbol indexing."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from mmaudit.models.schemas import (
    SolidityEntity,
    SolidityEntityKind,
    SolidityProjectMetadata,
    SolidityProvenance,
    SolidityStorageEntry,
    SoliditySymbolIndex,
)
from mmaudit.repository.chunking import line_range_hash
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult
from mmaudit.repository.ignore import normalize_relative_path


@dataclass(frozen=True)
class AstDocument:
    source_path: str
    ast: dict[str, Any]
    provenance: SolidityProvenance = SolidityProvenance.COMPILER


@dataclass(frozen=True)
class SolidityIndexBuild:
    index: SoliditySymbolIndex
    ast_documents: list[AstDocument]
    ast_entity_ids: dict[tuple[str, int], str] = field(default_factory=dict)
    contract_entity_by_name: dict[str, str] = field(default_factory=dict)
    function_entity_by_contract_name: dict[tuple[str, str], str] = field(default_factory=dict)
    modifier_entity_by_contract_name: dict[tuple[str, str], str] = field(default_factory=dict)
    storage_layout: list[SolidityStorageEntry] = field(default_factory=list)


def build_solidity_index(
    discovery: DiscoveryResult,
    projects: list[SolidityProjectMetadata],
    artifact_roots: list[Path],
) -> SolidityIndexBuild:
    """Build a normalized symbol index from compiler ASTs with source fallback."""

    solidity_files = [item for item in discovery.files if item.language == "Solidity"]
    by_path = {item.relative_path: item for item in solidity_files}
    ast_documents, ast_warnings = _load_ast_documents(artifact_roots, projects, by_path)
    entities: list[SolidityEntity] = []
    ast_entity_ids: dict[tuple[str, int], str] = {}
    contract_entity_by_name: dict[str, str] = {}
    function_entity_by_contract_name: dict[tuple[str, str], str] = {}
    modifier_entity_by_contract_name: dict[tuple[str, str], str] = {}
    indexed_ast_documents: list[AstDocument] = []
    warnings = list(ast_warnings)
    for document in ast_documents:
        file = by_path.get(document.source_path)
        if file is None:
            warnings.append(f"{document.source_path}: compiler AST source not present in discovery")
            continue
        parsed = _entities_from_ast(document, file)
        if not parsed:
            warnings.append(
                f"{document.source_path}: compiler AST had no exact entity spans; "
                "using fallback parser"
            )
            continue
        indexed_ast_documents.append(document)
        for entity, ast_id in parsed:
            entities.append(entity)
            if ast_id is not None:
                ast_entity_ids[(entity.path, ast_id)] = entity.id
            if entity.kind in {
                SolidityEntityKind.CONTRACT,
                SolidityEntityKind.INTERFACE,
                SolidityEntityKind.LIBRARY,
            }:
                contract_entity_by_name.setdefault(entity.name, entity.id)
            elif (
                entity.kind
                in {
                    SolidityEntityKind.FUNCTION,
                    SolidityEntityKind.CONSTRUCTOR,
                }
                and entity.contract_name
            ):
                function_entity_by_contract_name.setdefault(
                    (entity.contract_name, entity.name), entity.id
                )
            elif entity.kind is SolidityEntityKind.MODIFIER and entity.contract_name:
                modifier_entity_by_contract_name.setdefault(
                    (entity.contract_name, entity.name), entity.id
                )
    ast_sources = sorted({document.source_path for document in indexed_ast_documents})
    fallback_sources: list[str] = []
    for file in solidity_files:
        if file.relative_path in ast_sources:
            continue
        fallback_sources.append(file.relative_path)
        fallback_entities = _fallback_entities(file)
        for entity in fallback_entities:
            entities.append(entity)
            if entity.kind in {
                SolidityEntityKind.CONTRACT,
                SolidityEntityKind.INTERFACE,
                SolidityEntityKind.LIBRARY,
            }:
                contract_entity_by_name.setdefault(entity.name, entity.id)
            elif (
                entity.kind
                in {
                    SolidityEntityKind.FUNCTION,
                    SolidityEntityKind.CONSTRUCTOR,
                }
                and entity.contract_name
            ):
                function_entity_by_contract_name.setdefault(
                    (entity.contract_name, entity.name), entity.id
                )
            elif entity.kind is SolidityEntityKind.MODIFIER and entity.contract_name:
                modifier_entity_by_contract_name.setdefault(
                    (entity.contract_name, entity.name), entity.id
                )
    index = SoliditySymbolIndex(
        projects=projects,
        entities=sorted(entities, key=lambda entity: (entity.path, entity.start_line, entity.id)),
        ast_sources=ast_sources,
        fallback_sources=sorted(fallback_sources),
        warnings=warnings,
    )
    storage_layout, storage_warnings = _load_storage_layouts(
        artifact_roots,
        projects,
        by_path,
        entities,
    )
    index = index.model_copy(update={"warnings": [*index.warnings, *storage_warnings]})
    return SolidityIndexBuild(
        index=index,
        ast_documents=indexed_ast_documents,
        ast_entity_ids=ast_entity_ids,
        contract_entity_by_name=contract_entity_by_name,
        function_entity_by_contract_name=function_entity_by_contract_name,
        modifier_entity_by_contract_name=modifier_entity_by_contract_name,
        storage_layout=storage_layout,
    )


def _load_ast_documents(
    artifact_roots: list[Path],
    projects: list[SolidityProjectMetadata],
    by_path: dict[str, DiscoveredFile],
) -> tuple[list[AstDocument], list[str]]:
    documents: dict[str, AstDocument] = {}
    warnings: list[str] = []
    for artifact in [path for root in artifact_roots for path in root.glob("**/*.json")][:4_000]:
        try:
            payload = json.loads(artifact.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload.get("ast"), dict):
            source = _artifact_source_name(payload)
            resolved = _resolve_source_path(source, projects, by_path)
            if resolved:
                ast = payload["ast"]
                if _ast_document_matches_source(ast, by_path[resolved].content):
                    documents.setdefault(resolved, AstDocument(source_path=resolved, ast=ast))
                else:
                    warnings.append(
                        f"{resolved}: artifact AST byte spans did not match current source"
                    )
            elif source:
                warnings.append(f"{source}: artifact AST source could not be mapped to repository")
        output = payload.get("output", {})
        if isinstance(output, dict):
            sources = output.get("sources", {})
            if isinstance(sources, dict):
                for source, item in sources.items():
                    if not isinstance(item, dict) or not isinstance(item.get("ast"), dict):
                        continue
                    resolved = _resolve_source_path(str(source), projects, by_path)
                    if resolved:
                        ast = item["ast"]
                        if _ast_document_matches_source(ast, by_path[resolved].content):
                            documents.setdefault(
                                resolved,
                                AstDocument(source_path=resolved, ast=ast),
                            )
                        else:
                            warnings.append(
                                f"{resolved}: build-info AST byte spans did not match current "
                                "source"
                            )
                    else:
                        warnings.append(
                            f"{source}: build-info AST source could not be mapped to repository"
                        )
    return list(documents.values()), warnings


def _parse_src_components(src: str) -> tuple[int, int, int] | None:
    parts = src.split(":")
    if len(parts) != 3:
        return None
    try:
        return int(parts[0]), int(parts[1]), int(parts[2])
    except ValueError:
        return None


def _ast_document_matches_source(ast: dict[str, Any], content: str) -> bool:
    """Require every present compiler span to bind to one current source byte inventory."""

    expected_source_id: int | None = None
    observed_span = False
    source_size = len(content.encode("utf-8"))
    pending: list[Any] = [ast]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            if "src" in current:
                span = _parse_src_components(str(current["src"]))
                if span is None:
                    return False
                start, length, source_id = span
                if expected_source_id is None:
                    expected_source_id = source_id
                observed_span = True
                if (
                    source_id != expected_source_id
                    or start < 0
                    or length < 0
                    or start >= source_size
                    or start + length > source_size
                ):
                    return False
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return observed_span and expected_source_id is not None and expected_source_id >= 0


def _load_storage_layouts(
    artifact_roots: list[Path],
    projects: list[SolidityProjectMetadata],
    by_path: dict[str, DiscoveredFile],
    entities: list[SolidityEntity],
) -> tuple[list[SolidityStorageEntry], list[str]]:
    """Load compiler storage layouts from Foundry artifacts and build-info."""

    layouts: list[SolidityStorageEntry] = []
    warnings: list[str] = []
    state_entities = {
        (entity.contract_name, entity.name): entity
        for entity in entities
        if entity.contract_name
        and entity.kind
        in {
            SolidityEntityKind.STATE_VARIABLE,
            SolidityEntityKind.IMMUTABLE,
            SolidityEntityKind.CONSTANT,
        }
    }
    artifacts = [path for root in artifact_roots for path in root.glob("**/*.json")][:4_000]
    for artifact in artifacts:
        try:
            payload = json.loads(artifact.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        direct_layout = payload.get("storageLayout")
        if isinstance(direct_layout, dict):
            source = _resolve_source_path(_artifact_source_name(payload), projects, by_path)
            contract_name = str(payload.get("contractName", ""))
            if source and contract_name:
                layouts.extend(
                    _storage_entries(
                        source,
                        contract_name,
                        direct_layout,
                        state_entities,
                        warnings,
                    )
                )
        output = payload.get("output")
        if not isinstance(output, dict):
            continue
        contracts = output.get("contracts")
        if not isinstance(contracts, dict):
            continue
        for source_name, source_contracts in contracts.items():
            if not isinstance(source_contracts, dict):
                continue
            source = _resolve_source_path(str(source_name), projects, by_path)
            if source is None:
                continue
            for contract_name, contract_payload in source_contracts.items():
                if not isinstance(contract_payload, dict):
                    continue
                layout = contract_payload.get("storageLayout")
                if isinstance(layout, dict):
                    layouts.extend(
                        _storage_entries(
                            source,
                            str(contract_name),
                            layout,
                            state_entities,
                            warnings,
                        )
                    )
    unique = {entry.id: entry for entry in layouts}
    return (
        sorted(
            unique.values(),
            key=lambda item: (
                item.path,
                item.contract_name,
                _storage_slot_sort_key(item.slot),
                item.offset,
                item.variable_name,
            ),
        ),
        warnings,
    )


def _storage_entries(
    source: str,
    contract_name: str,
    layout: dict[str, Any],
    state_entities: dict[tuple[str, str], SolidityEntity],
    warnings: list[str],
) -> list[SolidityStorageEntry]:
    raw_storage = layout.get("storage", [])
    types = layout.get("types", {})
    if not isinstance(raw_storage, list) or not isinstance(types, dict):
        return []
    entries: list[SolidityStorageEntry] = []
    for position, raw in enumerate(raw_storage):
        if not isinstance(raw, dict):
            continue
        label = str(raw.get("label", f"storage_{position}"))
        raw_contract = str(raw.get("contract", ""))
        declared_contract = raw_contract.rsplit(":", 1)[-1] if raw_contract else ""
        entity = state_entities.get((declared_contract, label)) or state_entities.get(
            (contract_name, label)
        )
        if entity is None:
            candidates = [
                candidate
                for (candidate_contract, candidate_name), candidate in state_entities.items()
                if candidate_name == label and candidate.path == source
            ]
            if len(candidates) == 1:
                entity = candidates[0]
        if entity is None:
            warnings.append(
                f"{source}:{contract_name}.{label}: compiler storage entry was not indexed"
            )
            continue
        type_id = str(raw.get("type", "unknown"))
        type_payload = types.get(type_id, {})
        type_name = (
            str(type_payload.get("label", type_id)) if isinstance(type_payload, dict) else type_id
        )
        byte_size: int | None = None
        if isinstance(type_payload, dict):
            raw_byte_size = type_payload.get("numberOfBytes")
            try:
                byte_size = int(raw_byte_size) if raw_byte_size is not None else None
            except (TypeError, ValueError):
                byte_size = None
        try:
            offset = int(raw.get("offset", 0))
        except (TypeError, ValueError):
            offset = 0
        slot = str(raw.get("slot", position))
        try:
            ast_id = int(raw["astId"]) if raw.get("astId") is not None else None
        except (TypeError, ValueError):
            ast_id = None
        entry_id = _storage_entry_id(contract_name, label, slot, offset)
        entries.append(
            SolidityStorageEntry(
                id=entry_id,
                contract_name=contract_name,
                declaring_contract_name=entity.contract_name,
                variable_name=label,
                type_name=type_name,
                slot=slot,
                offset=offset,
                byte_size=byte_size,
                ast_id=ast_id,
                path=entity.path,
                start_line=entity.start_line,
                end_line=entity.end_line,
                source_hash=entity.source_hash,
                provenance=SolidityProvenance.COMPILER,
                confidence=0.99,
                transformation="solc_storageLayout.storage",
            )
        )
    return entries


def _storage_slot_sort_key(value: str) -> tuple[int, str]:
    try:
        return (int(value, 0), "")
    except ValueError:
        return (2**256 - 1, value)


def _storage_entry_id(
    contract_name: str,
    variable_name: str,
    slot: str,
    offset: int,
) -> str:
    payload = "\0".join((contract_name, variable_name, slot, str(offset)))
    return "storage-" + hashlib.sha256(payload.encode()).hexdigest()[:20]


def _artifact_source_name(payload: dict[str, Any]) -> str | None:
    if source := payload.get("sourceName"):
        return str(source)
    ast = payload.get("ast", {})
    if isinstance(ast, dict) and ast.get("absolutePath"):
        return str(ast["absolutePath"])
    metadata = payload.get("metadata")
    if isinstance(metadata, str):
        try:
            parsed = json.loads(metadata)
        except json.JSONDecodeError:
            return None
        targets = parsed.get("settings", {}).get("compilationTarget", {})
        if isinstance(targets, dict) and targets:
            return str(next(iter(targets)))
    return None


def _resolve_source_path(
    source: str | None,
    projects: list[SolidityProjectMetadata],
    by_path: dict[str, DiscoveredFile],
) -> str | None:
    if not source:
        return None
    normalized = source.replace("\\", "/")
    if "/workspace/" in normalized:
        normalized = normalized.split("/workspace/", 1)[1]
    candidates = [normalized.lstrip("./")]
    for project in projects:
        if project.project_root != ".":
            candidates.append(f"{project.project_root}/{normalized.lstrip('./')}")
    for candidate in candidates:
        try:
            safe = normalize_relative_path(candidate)
        except ValueError:
            continue
        if safe in by_path:
            return safe
    basename = PurePosixPath(normalized).name
    matches = [path for path in by_path if PurePosixPath(path).name == basename]
    return matches[0] if len(matches) == 1 else None


def _entities_from_ast(
    document: AstDocument,
    file: DiscoveredFile,
) -> list[tuple[SolidityEntity, int | None]]:
    entities: list[tuple[SolidityEntity, int | None]] = []
    for node in document.ast.get("nodes", []):
        if not isinstance(node, dict) or node.get("nodeType") != "ContractDefinition":
            continue
        contract_name = str(node.get("name", ""))
        contract_entity = _entity_from_node(
            file=file,
            node=node,
            kind=_contract_kind(str(node.get("contractKind", "contract"))),
            name=contract_name,
            contract_name=None,
            provenance=document.provenance,
            confidence=0.95,
        )
        if contract_entity is None:
            continue
        entities.append((contract_entity, _ast_id(node)))
        for child in node.get("nodes", []):
            if not isinstance(child, dict):
                continue
            child_entity = _child_entity(file, child, contract_name, document.provenance)
            if child_entity is not None:
                entities.append((child_entity, _ast_id(child)))
            if child.get("nodeType") == "VariableDeclarationStatement":
                for declaration in child.get("declarations", []) or []:
                    if isinstance(declaration, dict):
                        variable = _variable_entity(
                            file, declaration, contract_name, document.provenance
                        )
                        if variable is not None:
                            entities.append((variable, _ast_id(declaration)))
    return entities


def _child_entity(
    file: DiscoveredFile,
    node: dict[str, Any],
    contract_name: str,
    provenance: SolidityProvenance,
) -> SolidityEntity | None:
    node_type = node.get("nodeType")
    if node_type == "FunctionDefinition":
        kind_raw = str(node.get("kind", "function"))
        name = str(node.get("name") or kind_raw)
        kind = (
            SolidityEntityKind.CONSTRUCTOR
            if kind_raw == "constructor"
            else SolidityEntityKind.FUNCTION
        )
        return _entity_from_node(
            file=file,
            node=node,
            kind=kind,
            name=name,
            contract_name=contract_name,
            provenance=provenance,
            confidence=0.95,
            visibility=node.get("visibility"),
            mutability=node.get("stateMutability"),
            payable=node.get("stateMutability") == "payable",
            signature=_function_signature(node, name),
            selector=(str(node["functionSelector"]) if node.get("functionSelector") else None),
            return_types=_function_return_types(node),
            documentation=_documentation(node.get("documentation")),
        )
    if node_type == "ModifierDefinition":
        return _entity_from_node(
            file=file,
            node=node,
            kind=SolidityEntityKind.MODIFIER,
            name=str(node.get("name", "")),
            contract_name=contract_name,
            provenance=provenance,
            confidence=0.95,
            visibility=node.get("visibility"),
        )
    if node_type == "EventDefinition":
        return _entity_from_node(
            file=file,
            node=node,
            kind=SolidityEntityKind.EVENT,
            name=str(node.get("name", "")),
            contract_name=contract_name,
            provenance=provenance,
            confidence=0.95,
        )
    if node_type == "ErrorDefinition":
        return _entity_from_node(
            file=file,
            node=node,
            kind=SolidityEntityKind.ERROR,
            name=str(node.get("name", "")),
            contract_name=contract_name,
            provenance=provenance,
            confidence=0.95,
        )
    if node_type == "StructDefinition":
        return _entity_from_node(
            file=file,
            node=node,
            kind=SolidityEntityKind.STRUCT,
            name=str(node.get("name", "")),
            contract_name=contract_name,
            provenance=provenance,
            confidence=0.95,
        )
    if node_type == "EnumDefinition":
        return _entity_from_node(
            file=file,
            node=node,
            kind=SolidityEntityKind.ENUM,
            name=str(node.get("name", "")),
            contract_name=contract_name,
            provenance=provenance,
            confidence=0.95,
        )
    if node_type == "VariableDeclaration":
        return _variable_entity(file, node, contract_name, provenance)
    return None


def _variable_entity(
    file: DiscoveredFile,
    node: dict[str, Any],
    contract_name: str,
    provenance: SolidityProvenance,
) -> SolidityEntity | None:
    if node.get("stateVariable") is not True and node.get("mutability") not in {
        "constant",
        "immutable",
    }:
        return None
    mutability = str(node.get("mutability", "mutable"))
    kind = SolidityEntityKind.STATE_VARIABLE
    if mutability == "constant":
        kind = SolidityEntityKind.CONSTANT
    elif mutability == "immutable":
        kind = SolidityEntityKind.IMMUTABLE
    return _entity_from_node(
        file=file,
        node=node,
        kind=kind,
        name=str(node.get("name", "")),
        contract_name=contract_name,
        provenance=provenance,
        confidence=0.95,
        visibility=node.get("visibility"),
        mutability=mutability,
        signature=_state_getter_signature(node),
        return_types=_state_getter_return_types(node),
    )


def _entity_from_node(
    *,
    file: DiscoveredFile,
    node: dict[str, Any],
    kind: SolidityEntityKind,
    name: str,
    contract_name: str | None,
    provenance: SolidityProvenance,
    confidence: float,
    visibility: Any = None,
    mutability: Any = None,
    payable: bool = False,
    signature: str | None = None,
    selector: str | None = None,
    return_types: list[str] | None = None,
    documentation: str | None = None,
) -> SolidityEntity | None:
    source_range = _line_range_from_src(file.content, str(node.get("src", "")))
    if source_range is None:
        return None
    byte_start, byte_end, start_line, end_line, bounded = source_range
    transformation = f"solc_ast.{node.get('nodeType', kind.value)}"
    if bounded:
        transformation += ".bounded_to_source_length"
        confidence = min(confidence, 0.9)
    return SolidityEntity(
        id=_entity_id(kind.value, file.relative_path, start_line, name, contract_name),
        kind=kind,
        name=name or kind.value,
        contract_name=contract_name,
        path=file.relative_path,
        start_line=start_line,
        end_line=end_line,
        byte_start=byte_start,
        byte_end=byte_end,
        source_hash=line_range_hash(file.content, start_line, end_line),
        provenance=provenance,
        confidence=confidence,
        transformation=transformation,
        visibility=str(visibility) if visibility else None,
        mutability=str(mutability) if mutability else None,
        payable=payable,
        signature=signature,
        selector=selector,
        return_types=return_types or [],
        documentation=documentation,
    )


def _fallback_entities(file: DiscoveredFile) -> list[SolidityEntity]:
    lines = file.content.splitlines()
    entities: list[SolidityEntity] = []
    contract_stack: list[tuple[str, int]] = []
    declaration = re.compile(r"\b(contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)")
    function_re = re.compile(
        r"\b(function|modifier|constructor)\s*([A-Za-z_][A-Za-z0-9_]*)?\s*"
        r"(?P<parameters>\([^)]*\))?"
    )
    event_re = re.compile(r"\bevent\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    mapping_re = re.compile(
        r"^\s*mapping\s*\([^;]+\)\s+"
        r"(?:(?:public|private|internal|immutable|constant)\s+)*"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)"
    )
    variable_re = re.compile(
        r"^\s*(?:[A-Za-z_][A-Za-z0-9_<>,\[\]. ]+\s+)+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)"
    )
    for index, line in enumerate(lines, start=1):
        current_contract = contract_stack[-1][0] if contract_stack else None
        if match := declaration.search(line):
            name = match.group(2)
            contract_stack.append((name, _brace_depth(lines[:index])))
            current_contract = name
            entities.append(
                _fallback_entity(
                    file,
                    _contract_kind(match.group(1)),
                    name,
                    None,
                    index,
                    _fallback_block_end(lines, index),
                )
            )
        else:
            while contract_stack and _brace_depth(lines[:index]) < contract_stack[-1][1]:
                contract_stack.pop()
            current_contract = contract_stack[-1][0] if contract_stack else None
        if current_contract and (match := function_re.search(line)):
            raw_kind = match.group(1)
            name = match.group(2) or raw_kind
            kind = (
                SolidityEntityKind.MODIFIER
                if raw_kind == "modifier"
                else SolidityEntityKind.FUNCTION
            )
            if raw_kind == "constructor":
                kind = SolidityEntityKind.CONSTRUCTOR
            entities.append(
                _fallback_entity(
                    file,
                    kind,
                    name,
                    current_contract,
                    index,
                    _fallback_block_end(lines, index),
                    signature=_fallback_signature(
                        name,
                        match.group("parameters"),
                    )
                    if kind
                    in {
                        SolidityEntityKind.FUNCTION,
                        SolidityEntityKind.CONSTRUCTOR,
                    }
                    else None,
                    visibility=_fallback_visibility(line),
                    mutability=_fallback_mutability(line),
                    payable=bool(re.search(r"\bpayable\b", line)),
                )
            )
        elif current_contract and (match := event_re.search(line)):
            entities.append(
                _fallback_entity(
                    file,
                    SolidityEntityKind.EVENT,
                    match.group(1),
                    current_contract,
                    index,
                    index,
                )
            )
        elif current_contract:
            state_match = mapping_re.search(line)
            if state_match is None and ";" in line and "(" not in line:
                state_match = variable_re.search(line)
            if state_match is not None:
                entities.append(
                    _fallback_entity(
                        file,
                        SolidityEntityKind.STATE_VARIABLE,
                        state_match.group("name"),
                        current_contract,
                        index,
                        index,
                    )
                )
    return entities


def _fallback_entity(
    file: DiscoveredFile,
    kind: SolidityEntityKind,
    name: str,
    contract_name: str | None,
    start_line: int,
    end_line: int,
    *,
    signature: str | None = None,
    visibility: str | None = None,
    mutability: str | None = None,
    payable: bool = False,
) -> SolidityEntity:
    byte_start, byte_end = _line_byte_range(file.content, start_line, end_line)
    return SolidityEntity(
        id=_entity_id(kind.value, file.relative_path, start_line, name, contract_name),
        kind=kind,
        name=name,
        contract_name=contract_name,
        path=file.relative_path,
        start_line=start_line,
        end_line=max(start_line, end_line),
        byte_start=byte_start,
        byte_end=byte_end,
        source_hash=line_range_hash(file.content, start_line, max(start_line, end_line)),
        provenance=SolidityProvenance.FALLBACK,
        confidence=0.55,
        transformation=_fallback_transformation(kind),
        signature=signature,
        visibility=visibility,
        mutability=mutability,
        payable=payable,
    )


def _function_signature(node: dict[str, Any], name: str) -> str | None:
    parameters = node.get("parameters", {})
    if not isinstance(parameters, dict) or "parameters" not in parameters:
        return None
    raw_parameters = parameters.get("parameters")
    if not isinstance(raw_parameters, list):
        return None
    types: list[str] = []
    for parameter in raw_parameters:
        if not isinstance(parameter, dict):
            return None
        descriptions = parameter.get("typeDescriptions", {})
        raw_type = str(descriptions.get("typeString", "")) if isinstance(descriptions, dict) else ""
        normalized = _canonical_type(raw_type)
        if not normalized:
            return None
        types.append(normalized)
    return f"{name}({','.join(types)})"


def _function_return_types(node: dict[str, Any]) -> list[str]:
    returns = node.get("returnParameters", {})
    raw_parameters = returns.get("parameters") if isinstance(returns, dict) else None
    if not isinstance(raw_parameters, list):
        return []
    values: list[str] = []
    for parameter in raw_parameters:
        if not isinstance(parameter, dict):
            return []
        descriptions = parameter.get("typeDescriptions", {})
        raw_type = str(descriptions.get("typeString", "")) if isinstance(descriptions, dict) else ""
        normalized = _canonical_type(raw_type)
        if not normalized:
            return []
        values.append(normalized)
    return values


def _state_getter_signature(node: dict[str, Any]) -> str | None:
    if node.get("visibility") != "public":
        return None
    name = str(node.get("name", ""))
    raw_type = _node_type_string(node)
    if not name or not raw_type:
        return None
    keys, _value_type = _mapping_getter_types(raw_type)
    if keys is None:
        return None
    return f"{name}({','.join(keys)})"


def _state_getter_return_types(node: dict[str, Any]) -> list[str]:
    if node.get("visibility") != "public":
        return []
    raw_type = _node_type_string(node)
    if not raw_type:
        return []
    keys, value_type = _mapping_getter_types(raw_type)
    return [value_type] if keys is not None and value_type is not None else []


def _node_type_string(node: dict[str, Any]) -> str:
    descriptions = node.get("typeDescriptions", {})
    return str(descriptions.get("typeString", "")) if isinstance(descriptions, dict) else ""


def _mapping_getter_types(raw_type: str) -> tuple[list[str] | None, str | None]:
    value = raw_type.strip()
    keys: list[str] = []
    while value.startswith("mapping(") and value.endswith(")"):
        body = value[len("mapping(") : -1]
        split = _split_outer_mapping(body)
        if split is None:
            return None, None
        raw_key, value = split
        key = _canonical_type(raw_key.strip())
        if key is None:
            return None, None
        keys.append(key)
        value = value.strip()
    canonical_value = _canonical_type(value)
    if canonical_value is None:
        return None, None
    return keys, canonical_value


def _split_outer_mapping(value: str) -> tuple[str, str] | None:
    depth = 0
    for index in range(len(value) - 1):
        character = value[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif value[index : index + 2] == "=>" and depth == 0:
            return value[:index], value[index + 2 :]
    return None


def _fallback_signature(name: str, raw_parameters: str | None) -> str | None:
    if raw_parameters is None:
        return None
    body = raw_parameters[1:-1].strip()
    if not body:
        return f"{name}()"
    types: list[str] = []
    for parameter in body.split(","):
        cleaned = re.sub(r"\b(memory|calldata|storage|payable|indexed)\b", "", parameter)
        tokens = cleaned.split()
        if not tokens:
            return None
        normalized = _canonical_type(tokens[0])
        if not normalized:
            return None
        types.append(normalized)
    return f"{name}({','.join(types)})"


def _canonical_type(raw: str) -> str | None:
    value = re.sub(r"\s+(memory|calldata|storage)(\s|$)", " ", raw).strip()
    if value.startswith("contract "):
        return "address"
    if value == "address payable":
        return "address"
    if value == "uint":
        return "uint256"
    if value == "int":
        return "int256"
    if re.fullmatch(
        r"(?:u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?|address|bool|bytes(?:[1-9]|[12][0-9]|3[0-2])?|string)(?:\[[0-9]*\])*",
        value,
    ):
        return value
    return None


def _fallback_visibility(line: str) -> str | None:
    match = re.search(r"\b(public|external|internal|private)\b", line)
    return match.group(1) if match else None


def _fallback_mutability(line: str) -> str | None:
    match = re.search(r"\b(pure|view|payable)\b", line)
    return match.group(1) if match else None


def _line_range_from_src(content: str, src: str) -> tuple[int, int, int, int, bool] | None:
    parsed = _parse_src_components(src)
    if parsed is None:
        return None
    byte_start, byte_length, _file_index = parsed
    raw_byte_end = byte_start + byte_length
    encoded = content.encode()
    if byte_start < 0 or byte_length <= 0 or byte_start >= len(encoded):
        return None
    byte_end = min(raw_byte_end, len(encoded))
    start_line = encoded[:byte_start].count(b"\n") + 1
    end_line = encoded[: max(byte_start, byte_end - 1)].count(b"\n") + 1
    return (
        byte_start,
        byte_end,
        start_line,
        max(start_line, end_line),
        raw_byte_end > len(encoded),
    )


def _line_byte_range(content: str, start_line: int, end_line: int) -> tuple[int, int]:
    lines = content.splitlines(keepends=True)
    byte_start = len("".join(lines[: start_line - 1]).encode())
    byte_end = len("".join(lines[:end_line]).encode())
    return byte_start, max(byte_start, byte_end)


def _fallback_transformation(kind: SolidityEntityKind) -> str:
    if kind in {
        SolidityEntityKind.CONTRACT,
        SolidityEntityKind.INTERFACE,
        SolidityEntityKind.LIBRARY,
    }:
        return "bounded_source_contract_declaration"
    if kind in {
        SolidityEntityKind.FUNCTION,
        SolidityEntityKind.CONSTRUCTOR,
        SolidityEntityKind.MODIFIER,
    }:
        return "bounded_source_callable_declaration"
    if kind is SolidityEntityKind.EVENT:
        return "bounded_source_event_declaration"
    return "bounded_source_state_variable_declaration"


def _entity_id(
    kind: str,
    path: str,
    start_line: int,
    name: str,
    contract_name: str | None,
) -> str:
    payload = "\0".join((kind, path, str(start_line), contract_name or "", name))
    return "sol-" + hashlib.sha256(payload.encode()).hexdigest()[:20]


def _contract_kind(value: str) -> SolidityEntityKind:
    if value == "interface":
        return SolidityEntityKind.INTERFACE
    if value == "library":
        return SolidityEntityKind.LIBRARY
    return SolidityEntityKind.CONTRACT


def _ast_id(node: dict[str, Any]) -> int | None:
    try:
        return int(node["id"])
    except (KeyError, TypeError, ValueError):
        return None


def _documentation(value: Any) -> str | None:
    if isinstance(value, str):
        return value[:1_000]
    if isinstance(value, dict) and isinstance(value.get("text"), str):
        return str(value["text"])[:1_000]
    return None


def _fallback_block_end(lines: list[str], start_line: int) -> int:
    depth = 0
    seen_open = False
    for index in range(start_line, len(lines) + 1):
        line = lines[index - 1]
        depth += line.count("{")
        seen_open = seen_open or "{" in line
        depth -= line.count("}")
        if seen_open and depth <= 0:
            return index
        if not seen_open and line.rstrip().endswith(";"):
            return index
    return start_line


def _brace_depth(lines: list[str]) -> int:
    depth = 0
    for line in lines:
        depth += line.count("{") - line.count("}")
    return depth
