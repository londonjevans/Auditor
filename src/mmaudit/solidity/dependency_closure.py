"""Bounded dependency evidence over exact supplied bytes, without filesystem or compiler I/O.

Import completeness is lexical and namespace-scoped, not a Solidity compilation claim.
The existing semantic graph is retained before retrieval compaction, including omissions;
its heuristic or expression-labelled targets cannot earn static call completeness.
"""

from __future__ import annotations

import hashlib
import re
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from mmaudit.models.schemas import (
    SolidityGraphFactOmission,
    SolidityGraphKind,
    SolidityGraphOmission,
    SolidityProvenance,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult
from mmaudit.repository.redaction import detect_secrets
from mmaudit.repository.secrets import is_sensitive_workspace_path
from mmaudit.solidity.dependency_calls import (
    DependencyCallContext,
    build_dependency_call_context,
)
from mmaudit.solidity.dependency_scopes import (
    DependencyScopedContext,
    build_dependency_scoped_context,
)
from mmaudit.solidity.dependency_static_closure import (
    STATIC_CLOSURE_KINDS,
    DevelopmentStaticCallClosure,
    StaticClosureStatus,
    compute_static_call_closure,
)
from mmaudit.solidity.dependency_syntax import (
    DependencySyntaxContext,
    build_dependency_syntax_context,
)
from mmaudit.solidity.dependency_targets import (
    DependencyTargetContext,
    build_dependency_target_context,
)
from mmaudit.solidity.graphs import build_solidity_graphs
from mmaudit.solidity.index import build_solidity_index
from mmaudit.solidity.projects import _remappings

MAX_DEPENDENCY_SOURCES = 256
MAX_DEPENDENCY_FILE_BYTES = 262_144
MAX_DEPENDENCY_BYTES = 8_388_608
MAX_DEPENDENCY_RECORDS = 4096
# The composed witness must accommodate the admitted corpus, not only a small partition.
MAX_DEPENDENCY_WITNESS_BYTES = 4_194_304
LEGACY_DEPENDENCY_GRAPH_BYTES = 393_216
MAX_DEPENDENCY_GRAPH_BYTES = 2_097_152
MAX_DEPENDENCY_REMAPPING_BYTES = 32_768
MAX_DEPENDENCY_TOKENS = 131_072
_SHA = r"^[0-9a-f]{64}$"
_PATH = r"^(?:[A-Za-z0-9][A-Za-z0-9._-]*/)*[A-Za-z0-9][A-Za-z0-9._-]*\.sol$"
_IMPORT_PATH = re.compile(r"[A-Za-z0-9@_./-]{1,512}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_CALL_KINDS = frozenset(
    {
        SolidityGraphKind.INHERITANCE,
        SolidityGraphKind.INTERNAL_CALL,
        SolidityGraphKind.EXTERNAL_CALL,
        SolidityGraphKind.LOW_LEVEL_CALL,
        SolidityGraphKind.DELEGATECALL,
        SolidityGraphKind.CONTRACT_CREATION,
    }
)
type ImportClosureStatus = Literal["NOT_ESTABLISHED", "IMPORT_CLOSED"]
type DependencyClosureStatus = Literal["NOT_ESTABLISHED", "IMPORT_CLOSED", "CALL_CLOSED"]
type DependencyReferenceKind = Literal[
    "MEMBER_CALL", "INHERITANCE_HEADER", "NEW_TYPE", "ASSEMBLY", "USING"
]
_REFERENCE_KEYWORDS: dict[str, DependencyReferenceKind] = {
    "is": "INHERITANCE_HEADER",
    "new": "NEW_TYPE",
    "assembly": "ASSEMBLY",
    "using": "USING",
}
type ImportShortfall = Literal[
    "MALFORMED_IMPORT",
    "UNSUPPORTED_IMPORT_PATH",
    "OUTSIDE_SUPPLIED_NAMESPACE",
    "MISSING_SUPPLIED_SOURCE",
    "AMBIGUOUS_REMAPPING",
]


class _DependencyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class DependencySource(_DependencyModel):
    filename: str = Field(pattern=_PATH, max_length=512)
    sha256: str = Field(pattern=_SHA)
    size: int = Field(gt=0, le=MAX_DEPENDENCY_FILE_BYTES)


class DependencyImport(_DependencyModel):
    source: str = Field(pattern=_PATH, max_length=512)
    byte_start: int = Field(ge=0, lt=MAX_DEPENDENCY_FILE_BYTES)
    byte_end: int = Field(gt=0, le=MAX_DEPENDENCY_FILE_BYTES)
    line: int = Field(ge=1, le=10_000)
    import_path: str | None = Field(default=None, max_length=512)
    target: str | None = Field(default=None, pattern=_PATH, max_length=512)
    shortfall: ImportShortfall | None = None

    @model_validator(mode="after")
    def resolved_or_missing(self) -> Self:
        if self.byte_end <= self.byte_start or (self.target is None) != (
            self.shortfall is not None
        ):
            raise ValueError("dependency import must have an exact span and resolution outcome")
        return self


class DependencyParseGap(_DependencyModel):
    source: str = Field(pattern=_PATH, max_length=512)
    byte_offset: int = Field(ge=0, le=MAX_DEPENDENCY_FILE_BYTES)
    reason: Literal["LEXICAL_ERROR", "UNBALANCED_DELIMITER", "IMPORT_NOT_TOP_LEVEL"]


class DependencyGraphFact(_DependencyModel):
    source: str = Field(pattern=_PATH, max_length=512)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    kind: SolidityGraphKind
    provenance: SolidityProvenance
    confidence: float = Field(ge=0, le=1)
    fact_sha256: str = Field(pattern=_SHA)
    source_id: str = Field(min_length=1, max_length=512)
    target_id: str = Field(min_length=1, max_length=512)
    resolution: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"


class DependencyCandidateReference(_DependencyModel):
    """A lexical candidate, including graph-missed calls; never a complete type/call proof."""

    source: str = Field(pattern=_PATH, max_length=512)
    byte_start: int = Field(ge=0, lt=MAX_DEPENDENCY_FILE_BYTES)
    byte_end: int = Field(gt=0, le=MAX_DEPENDENCY_FILE_BYTES)
    line: int = Field(ge=1, le=10_000)
    kind: DependencyReferenceKind
    spelling: str = Field(min_length=1, max_length=512)
    target_resolution: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    basis: Literal["LEXICAL_CANDIDATE_NOT_COMPLETE_SEMANTIC_CALL_INVENTORY"] = (
        "LEXICAL_CANDIDATE_NOT_COMPLETE_SEMANTIC_CALL_INVENTORY"
    )


class DependencyPrimaryClosure(_DependencyModel):
    primary: str = Field(pattern=_PATH, max_length=512)
    import_members: tuple[str, ...] = Field(min_length=1, max_length=MAX_DEPENDENCY_SOURCES)
    import_closure: ImportClosureStatus
    call_closure: StaticClosureStatus = "NOT_ESTABLISHED"
    call_shortfall: (
        Literal[
            "COMPLETE_STATIC_TARGET_AND_IMPLEMENTER_RESOLUTION_UNAVAILABLE",
            "STATIC_CLOSURE_SHORTFALLS_RECORDED",
        ]
        | None
    ) = "COMPLETE_STATIC_TARGET_AND_IMPLEMENTER_RESOLUTION_UNAVAILABLE"
    call_members: tuple[str, ...] | None = Field(default=None, min_length=1, max_length=256)

    @model_serializer(mode="wrap")
    def preserve_legacy_primary(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        result: dict[str, Any] = handler(self)
        if self.call_members is None:
            result.pop("call_members", None)
        return result


class DevelopmentDependencyClosure(_DependencyModel):
    """Self-hashes bind evidence; the source consumer must additionally recompute it."""

    schema_version: Literal["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7"] = "1.0"
    scope: Literal["EXACT_SUPPLIED_SOURCE_SET_NOT_FILESYSTEM_OR_DEPLOYMENT_COMPLETENESS"] = (
        "EXACT_SUPPLIED_SOURCE_SET_NOT_FILESYSTEM_OR_DEPLOYMENT_COMPLETENESS"
    )
    resolution_policy: Literal["LOCAL_RELATIVE_UNIQUE_LONGEST_PREFIX_IMPORTS_V1"] = (
        "LOCAL_RELATIVE_UNIQUE_LONGEST_PREFIX_IMPORTS_V1"
    )
    parse_scope: Literal["DEPENDENCY_LEXER_NOT_SOLIDITY_COMPILATION"] = (
        "DEPENDENCY_LEXER_NOT_SOLIDITY_COMPILATION"
    )
    source_inventory: tuple[DependencySource, ...] = Field(
        min_length=1, max_length=MAX_DEPENDENCY_SOURCES
    )
    source_inventory_sha256: str = Field(pattern=_SHA)
    remapping_text: str = Field(max_length=MAX_DEPENDENCY_REMAPPING_BYTES)
    remapping_sha256: str = Field(pattern=_SHA)
    unsupported_remapping_lines: tuple[int, ...] = Field(max_length=MAX_DEPENDENCY_RECORDS)
    imports: tuple[DependencyImport, ...] = Field(max_length=MAX_DEPENDENCY_RECORDS)
    parse_gaps: tuple[DependencyParseGap, ...] = Field(max_length=MAX_DEPENDENCY_RECORDS)
    candidate_references: tuple[DependencyCandidateReference, ...] = Field(
        max_length=MAX_DEPENDENCY_RECORDS
    )
    graph_sha256: str = Field(pattern=_SHA)
    graph_generation_complete: bool
    graph_artifact_byte_limit: int = Field(ge=1024, le=MAX_DEPENDENCY_GRAPH_BYTES)
    graph_edge_omissions: tuple[SolidityGraphOmission, ...] = Field(max_length=64)
    graph_fact_omissions: tuple[SolidityGraphFactOmission, ...] = Field(max_length=3)
    graph_warnings: tuple[str, ...] = Field(max_length=MAX_DEPENDENCY_RECORDS)
    graph_edge_omission_sha256: str = Field(pattern=_SHA)
    graph_fact_omission_sha256: str = Field(pattern=_SHA)
    graph_warnings_sha256: str = Field(pattern=_SHA)
    graph_facts: tuple[DependencyGraphFact, ...] = Field(max_length=MAX_DEPENDENCY_RECORDS)
    primaries: tuple[DependencyPrimaryClosure, ...] = Field(
        min_length=1, max_length=MAX_DEPENDENCY_SOURCES
    )
    dependency_closure: DependencyClosureStatus
    target_context: DependencyTargetContext | None = None
    scoped_context: DependencyScopedContext | None = None
    call_context: DependencyCallContext | None = None
    syntax_context: DependencySyntaxContext | None = None
    static_call_closure: DevelopmentStaticCallClosure | None = None
    runtime_authority: Literal[False] = False
    qualification_eligible: Literal[False] = False
    audit_complete: Literal[False] = False
    witness_sha256: str = Field(pattern=_SHA)

    @model_serializer(mode="wrap")
    def preserve_import_witness_bytes(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        result: dict[str, Any] = handler(self)
        if self.target_context is None:
            result.pop("target_context", None)
        if self.scoped_context is None:
            result.pop("scoped_context", None)
        if self.call_context is None:
            result.pop("call_context", None)
        if self.syntax_context is None:
            result.pop("syntax_context", None)
        if self.static_call_closure is None:
            result.pop("static_call_closure", None)
        return result

    @field_validator("runtime_authority", "qualification_eligible", "audit_complete", mode="before")
    @classmethod
    def no_authority(cls, value: object) -> Literal[False]:
        if value is not False:
            raise ValueError("dependency evidence has no runtime or audit authority")
        return False

    @model_validator(mode="after")
    def exact_structure_and_digest(self) -> Self:
        paths = tuple(s.filename for s in self.source_inventory)
        if paths != tuple(sorted(set(paths))) or len({p.casefold() for p in paths}) != len(paths):
            raise ValueError("dependency source universe must be sorted and case-distinct")
        if sum(s.size for s in self.source_inventory) > MAX_DEPENDENCY_BYTES:
            raise ValueError("dependency source universe exceeds the byte ceiling")
        if tuple(p.primary for p in self.primaries) != paths:
            raise ValueError("dependency closure must retain every supplied primary")
        if (self.schema_version in {"1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7"}) != (
            self.target_context is not None
        ):
            raise ValueError("target context requires its explicit witness version")
        if (self.schema_version in {"1.2", "1.3", "1.4", "1.5", "1.6", "1.7"}) != (
            self.scoped_context is not None
        ):
            raise ValueError("scoped context requires its explicit witness version")
        if (self.schema_version in {"1.3", "1.4", "1.5", "1.6", "1.7"}) != (
            self.call_context is not None
        ):
            raise ValueError("typed call context requires its explicit witness version")
        if (self.schema_version in {"1.4", "1.5", "1.6", "1.7"}) != (
            self.syntax_context is not None
        ):
            raise ValueError("syntax context requires its explicit witness version")
        if (self.schema_version == "1.7") != (self.static_call_closure is not None):
            raise ValueError("static call closure requires its exact witness version")
        for version_context, modifier_policy, constructor_policy in (
            (
                self.scoped_context,
                "MODERN_LEXICAL_VALUES_AND_MODIFIER_HEADERS_V2",
                "MODERN_LEXICAL_VALUES_AND_CONSTRUCTOR_HEADERS_V3",
            ),
            (
                self.call_context,
                "SOURCE_CALL_AND_MODIFIER_RESOLUTION_V2",
                "SOURCE_CALL_MODIFIER_AND_CONSTRUCTOR_RESOLUTION_V3",
            ),
            (
                self.syntax_context,
                "SOURCE_GRAMMAR_AND_MODIFIER_CENSUS_V2",
                "SOURCE_GRAMMAR_AND_CONSTRUCTOR_CENSUS_V3",
            ),
        ):
            if version_context is not None and (version_context.policy == modifier_policy) != (
                self.schema_version == "1.5"
            ):
                raise ValueError(
                    "modifier context requires its exact witness and resolution versions"
                )
            if version_context is not None and (version_context.policy == constructor_policy) != (
                self.schema_version in {"1.6", "1.7"}
            ):
                raise ValueError(
                    "constructor context requires its exact witness and resolution versions"
                )
        if self.syntax_context is not None:
            if self.call_context is None:
                raise ValueError("syntax evidence lacks its complete typed-call context")
            self.syntax_context.validate_call_context(self.call_context)
            if tuple(
                (s.source, s.source_sha256, s.source_bytes) for s in self.syntax_context.sources
            ) != tuple((s.filename, s.sha256, s.size) for s in self.source_inventory):
                raise ValueError("syntax evidence changes its exact source inventory")
        if self.target_context is not None:
            context = self.target_context
            inventory = {s.filename: s for s in self.source_inventory}
            if (
                context.source_inventory_sha256 != self.source_inventory_sha256
                or tuple(p.primary for p in context.primaries) != paths
                or any(
                    d.source not in inventory
                    or d.source_sha256 != inventory[d.source].sha256
                    or d.byte_end > inventory[d.source].size
                    for d in context.declarations
                )
            ):
                raise ValueError(
                    "target context differs from its complete supplied source universe"
                )
        if self.scoped_context is not None:
            scoped = self.scoped_context
            if self.target_context is None:
                raise ValueError("scoped context lacks its source declaration universe")
            types = {d.id: d for d in self.target_context.declarations}
            if (
                scoped.source_inventory_sha256 != self.source_inventory_sha256
                or scoped.target_context_sha256
                != canonical_sha256(self.target_context.model_dump(mode="json"))
                or tuple(p.primary for p in scoped.primaries) != paths
                or scoped.supplied_type_ids != tuple(sorted(types))
                or any(
                    record.owner_type_id not in types
                    or record.source != types[record.owner_type_id].source
                    or record.source_sha256 != types[record.owner_type_id].source_sha256
                    or not types[record.owner_type_id].byte_start
                    <= record.byte_start
                    < record.byte_end
                    <= types[record.owner_type_id].byte_end
                    for record in (*scoped.scopes, *scoped.values, *scoped.functions)
                )
            ):
                raise ValueError(
                    "scoped declarations differ from their exact supplied source types"
                )
        if self.call_context is not None:
            context_calls = self.call_context
            if self.scoped_context is None or self.target_context is None:
                raise ValueError("typed calls lack their scoped declaration universe")
            type_ids = {d.id for d in self.target_context.declarations}
            scope_ids = {s.id for s in self.scoped_context.scopes}
            value_ids = {v.id for v in self.scoped_context.values}
            function_ids = {f.id for f in self.scoped_context.functions}
            types = {d.id: d for d in self.target_context.declarations}
            functions = {f.id: f for f in self.scoped_context.functions}
            scopes = {s.id: s for s in self.scoped_context.scopes}
            call_sites = {(c.source, c.call_byte_start): c for c in context_calls.calls}
            source_map = {s.filename: s for s in self.source_inventory}
            if (
                context_calls.source_inventory_sha256 != self.source_inventory_sha256
                or context_calls.scoped_context_sha256
                != canonical_sha256(self.scoped_context.model_dump(mode="json"))
                or tuple(p.primary for p in context_calls.primaries) != paths
            ):
                raise ValueError("typed calls differ from their exact scoped source universe")
            for call in context_calls.calls:
                construction = call.constructor_binding
                if construction is not None and (
                    not set(construction.required_type_ids) <= type_ids
                    or not set(construction.constructor_member_ids) <= function_ids
                    or any(
                        functions[i].kind != "constructor"
                        or functions[i].owner_type_id not in construction.required_type_ids
                        for i in construction.constructor_member_ids
                    )
                    or {functions[i].owner_type_id for i in construction.constructor_member_ids}
                    != set(construction.required_type_ids) - set(construction.implicit_type_ids)
                    or set(construction.implicit_type_ids)
                    & {functions[i].owner_type_id for i in construction.constructor_member_ids}
                    or any(
                        site.source != types[site.owner_type_id].source
                        for site in construction.base_argument_calls
                    )
                    or any(
                        (
                            (
                                child_scope := scopes.get(
                                    call_sites[site.source, site.call_byte_start].scope_id or ""
                                )
                            )
                            is None
                            or child_scope.owner_type_id != site.owner_type_id
                        )
                        for site in construction.base_argument_calls
                    )
                ):
                    raise ValueError("constructor evidence leaves its exact declaration universe")
                expressions = (*call.arguments, *((call.receiver,) if call.receiver else ()))
                expression_types = (*call.result_types, *(a.expression_type for a in expressions))
                if (
                    call.source_sha256 != source_map[call.source].sha256
                    or call.byte_end > source_map[call.source].size
                    or (call.scope_id is not None and call.scope_id not in scope_ids)
                    or not set(call.implementation_ids) <= type_ids
                    or not set(
                        (
                            *call.candidate_member_ids,
                            *call.member_ids,
                            *call.implementation_member_ids,
                        )
                    )
                    <= function_ids
                    or any(not set(a.value_ids) <= value_ids for a in expressions)
                    or any(
                        t.target_id is not None and t.target_id not in type_ids
                        for t in expression_types
                    )
                ):
                    raise ValueError("typed call leaves its exact source declaration universe")
        if any(
            p.import_members != tuple(sorted(set(p.import_members)))
            or p.primary not in p.import_members
            or not set(p.import_members) <= set(paths)
            for p in self.primaries
        ):
            raise ValueError("dependency primary membership differs from supplied sources")
        if any(
            i.source not in paths or (i.target is not None and i.target not in paths)
            for i in self.imports
        ):
            raise ValueError("dependency import leaves its supplied source universe")
        if (
            any(g.source not in paths for g in self.parse_gaps)
            or any(g.source not in paths for g in self.graph_facts)
            or any(g.source not in paths for g in self.candidate_references)
        ):
            raise ValueError("dependency gap/fact has no supplied source")
        if self.source_inventory_sha256 != canonical_sha256(
            [s.model_dump(mode="json") for s in self.source_inventory]
        ):
            raise ValueError("dependency source universe digest differs")
        if self.remapping_sha256 != hashlib.sha256(self.remapping_text.encode()).hexdigest():
            raise ValueError("dependency remapping digest differs")
        if self.graph_generation_complete is bool(
            self.graph_edge_omissions or self.graph_fact_omissions
        ):
            raise ValueError("dependency graph completeness differs from its omissions")
        if (
            self.graph_edge_omission_sha256
            != canonical_sha256([o.model_dump(mode="json") for o in self.graph_edge_omissions])
            or self.graph_fact_omission_sha256
            != canonical_sha256([o.model_dump(mode="json") for o in self.graph_fact_omissions])
            or self.graph_warnings_sha256 != canonical_sha256(list(self.graph_warnings))
        ):
            raise ValueError("dependency graph omissions/warnings digest differs")
        expected: DependencyClosureStatus = (
            "IMPORT_CLOSED"
            if all(p.import_closure == "IMPORT_CLOSED" for p in self.primaries)
            else "NOT_ESTABLISHED"
        )
        if self.static_call_closure is not None:
            self.static_call_closure.validate_inputs(self)
            expected = self.static_call_closure.call_closure
            for primary, proof in zip(
                self.primaries, self.static_call_closure.primaries, strict=True
            ):
                if (
                    primary.primary != proof.primary
                    or primary.call_members != proof.members
                    or primary.call_closure != proof.call_closure
                    or primary.call_shortfall
                    != (
                        None
                        if proof.call_closure == "CALL_CLOSED"
                        else "STATIC_CLOSURE_SHORTFALLS_RECORDED"
                    )
                ):
                    raise ValueError(
                        "primary call closure differs from its complete computed proof"
                    )
        elif any(
            p.call_closure != "NOT_ESTABLISHED"
            or p.call_members is not None
            or p.call_shortfall != "COMPLETE_STATIC_TARGET_AND_IMPLEMENTER_RESOLUTION_UNAVAILABLE"
            for p in self.primaries
        ):
            raise ValueError("legacy dependency witnesses cannot claim computed call closure")
        if self.dependency_closure != expected:
            raise ValueError("dependency aggregate differs from complete primary population")
        if (
            canonical_sha256(self.model_dump(mode="json", exclude={"witness_sha256"}))
            != self.witness_sha256
        ):
            raise ValueError("dependency witness digest differs")
        if len(self.model_dump_json().encode()) > MAX_DEPENDENCY_WITNESS_BYTES:
            raise ValueError("complete dependency witness exceeds the byte ceiling")
        return self


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str
    start: int
    end: int


def _tokens(content: bytes) -> tuple[tuple[_Token, ...], int | None]:
    """Scan bytes linearly; comment/string contents cannot invent or hide import tokens."""

    result: list[_Token] = []
    i = 0
    while i < len(content):
        c = content[i]
        if c in b" \t\r\n":
            i += 1
            continue
        if content[i : i + 2] == b"//":
            i += 2
            while i < len(content) and content[i] not in b"\r\n":
                i += 1
            continue
        if content[i : i + 2] == b"/*":
            end = content.find(b"*/", i + 2)
            if end < 0:
                return tuple(result), i
            i = end + 2
            continue
        start = i
        if c in b"\"'":
            quote = c
            i += 1
            while i < len(content) and content[i] != quote:
                if content[i] in b"\r\n":
                    return tuple(result), start
                i += 2 if content[i] == 92 else 1
            if i >= len(content):
                return tuple(result), start
            i += 1
            token = _Token("string", content[start + 1 : i - 1].decode("utf-8"), start, i)
        elif 65 <= c <= 90 or 97 <= c <= 122 or c in b"_$":
            i += 1
            while i < len(content) and (
                65 <= content[i] <= 90
                or 97 <= content[i] <= 122
                or 48 <= content[i] <= 57
                or content[i] in b"_$"
            ):
                i += 1
            token = _Token("identifier", content[start:i].decode("ascii"), start, i)
        else:
            if not 33 <= c <= 126 or c == 92:
                return tuple(result), start
            i += 1
            token = _Token("punctuation", chr(c), start, i)
        result.append(token)
        if len(result) > MAX_DEPENDENCY_TOKENS:
            raise ValueError("dependency lexer exceeds its token ceiling")
    return tuple(result), None


def _import_literal(tokens: tuple[_Token, ...]) -> str | None:
    values = [t.value for t in tokens]
    # import "x" [as X]; import * as X from "x"; import {X [as Y], ...} from "x";
    if (
        len(tokens) in {1, 3}
        and tokens[0].kind == "string"
        and (
            len(tokens) == 1
            or (
                values[1] == "as"
                and tokens[1].kind == tokens[2].kind == "identifier"
                and _IDENTIFIER.fullmatch(values[2])
            )
        )
    ):
        return values[0]
    if any(t.kind == "string" for t in tokens[:-1]):
        return None
    if (
        len(tokens) == 5
        and values[:2] == ["*", "as"]
        and _IDENTIFIER.fullmatch(values[2])
        and values[3] == "from"
        and tokens[4].kind == "string"
    ):
        return values[4]
    if (
        len(tokens) >= 5
        and values[0] == "{"
        and values[-3:-1] == ["}", "from"]
        and tokens[-1].kind == "string"
    ):
        body = values[1:-3]
        groups: list[list[str]] = [[]]
        for value in body:
            if value == ",":
                groups.append([])
            else:
                groups[-1].append(value)
        if all(
            len(g) in {1, 3}
            and _IDENTIFIER.fullmatch(g[0])
            and (len(g) == 1 or (g[1] == "as" and _IDENTIFIER.fullmatch(g[2])))
            for g in groups
        ):
            return values[-1]
    return None


def _mapping_rules(text: str) -> tuple[tuple[tuple[str, str], ...], tuple[int, ...]]:
    # Reuse project parsing, retaining every unsupported original line instead of dropping it.
    rules: list[tuple[str, str]] = []
    unsupported: list[int] = []
    for line, raw in enumerate(text.splitlines(), 1):
        parsed = _remappings(raw)
        if not parsed:
            continue
        value = parsed[0]
        parts = value.split("=")
        if len(parts) != 2 or any(
            not _IMPORT_PATH.fullmatch(p)
            or not p.endswith("/")
            or p.startswith(("/", "./", "../"))
            or any(s in {".", ".."} for s in p[:-1].split("/"))
            for p in parts
        ):
            unsupported.append(line)
        else:
            rules.append((parts[0], parts[1]))
    return tuple(rules), tuple(unsupported)


def _resolve_import(
    source: str, literal: str, paths: set[str], rules: tuple[tuple[str, str], ...]
) -> tuple[str | None, ImportShortfall | None]:
    if not _IMPORT_PATH.fullmatch(literal) or literal.startswith("/") or "//" in literal:
        return None, "UNSUPPORTED_IMPORT_PATH"
    relative = literal.startswith(("./", "../"))
    if not relative and any(part in {".", ".."} for part in literal.split("/")):
        return None, "UNSUPPORTED_IMPORT_PATH"
    parts = list(PurePosixPath(source).parent.parts) if relative else []
    for part in literal.split("/"):
        if part == "..":
            if not parts:
                return None, "OUTSIDE_SUPPLIED_NAMESPACE"
            parts.pop()
        elif part not in {"", "."}:
            parts.append(part)
    name = "/".join(parts)
    matching = [(prefix, target) for prefix, target in rules if name.startswith(prefix)]
    if matching:
        longest = max(len(prefix) for prefix, _ in matching)
        targets = {
            target + name[len(prefix) :] for prefix, target in matching if len(prefix) == longest
        }
        if len(targets) != 1:
            return None, "AMBIGUOUS_REMAPPING"
        name = next(iter(targets))
    if name not in paths:
        return None, "MISSING_SUPPLIED_SOURCE"
    return name, None


def _source_imports(
    source: str, content: bytes, paths: set[str], rules: tuple[tuple[str, str], ...]
) -> tuple[list[DependencyImport], list[DependencyParseGap], list[DependencyCandidateReference]]:
    tokens, failure = _tokens(content)
    gaps = (
        []
        if failure is None
        else [DependencyParseGap(source=source, byte_offset=failure, reason="LEXICAL_ERROR")]
    )
    imports: list[DependencyImport] = []
    references: list[DependencyCandidateReference] = []
    line_starts = [0]
    for line in content.splitlines(keepends=True):
        line_starts.append(line_starts[-1] + len(line))
    stack: list[_Token] = []
    closes = {"}": "{", "]": "[", ")": "("}
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.kind == "identifier" and token.value == "import":
            if stack:
                gaps.append(
                    DependencyParseGap(
                        source=source, byte_offset=token.start, reason="IMPORT_NOT_TOP_LEVEL"
                    )
                )
            j = i + 1
            while j < len(tokens) and not (
                tokens[j].kind == "punctuation" and tokens[j].value == ";"
            ):
                j += 1
            literal = _import_literal(tokens[i + 1 : j]) if j < len(tokens) else None
            target, shortfall = (
                (None, "MALFORMED_IMPORT")
                if literal is None
                else _resolve_import(source, literal, paths, rules)
            )
            imports.append(
                DependencyImport(
                    source=source,
                    byte_start=token.start,
                    byte_end=tokens[j].end if j < len(tokens) else len(content),
                    line=bisect_right(line_starts, token.start),
                    import_path=literal if literal is not None and len(literal) <= 512 else None,
                    target=target,
                    shortfall=shortfall,
                )
            )
            i = j + 1
            continue
        reference_kind: DependencyReferenceKind | None = None
        end = token.end
        spelling = token.value
        if (
            token.kind == "punctuation"
            and token.value == "."
            and i + 2 < len(tokens)
            and tokens[i + 1].kind == "identifier"
            and tokens[i + 2].kind == "punctuation"
            and tokens[i + 2].value in {"(", "{"}
        ):
            reference_kind = "MEMBER_CALL"
            spelling = tokens[i + 1].value
            end = tokens[i + 2].end
        elif token.kind == "identifier":
            reference_kind = _REFERENCE_KEYWORDS.get(token.value)
        if reference_kind is not None:
            references.append(
                DependencyCandidateReference(
                    source=source,
                    byte_start=token.start,
                    byte_end=end,
                    line=bisect_right(line_starts, token.start),
                    kind=reference_kind,
                    spelling=spelling,
                )
            )
            if len(references) > MAX_DEPENDENCY_RECORDS:
                raise ValueError(
                    "complete dependency candidate references exceed the record ceiling"
                )
        if token.kind == "punctuation":
            if token.value in {"{", "[", "("}:
                stack.append(token)
            elif token.value in closes:
                if not stack or stack[-1].value != closes[token.value]:
                    gaps.append(
                        DependencyParseGap(
                            source=source, byte_offset=token.start, reason="UNBALANCED_DELIMITER"
                        )
                    )
                else:
                    stack.pop()
        i += 1
    gaps.extend(
        DependencyParseGap(source=source, byte_offset=t.start, reason="UNBALANCED_DELIMITER")
        for t in stack
    )
    return imports, sorted(gaps, key=lambda g: (g.byte_offset, g.reason)), references


def compute_development_dependency_closure(
    *,
    source_files: tuple[tuple[str, bytes], ...],
    remapping_text: str = "",
    include_target_context: bool = False,
    include_scoped_context: bool = False,
    include_call_context: bool = False,
    include_syntax_context: bool = False,
    include_modifier_context: bool = False,
    include_constructor_context: bool = False,
    include_static_closure: bool = False,
    graph_artifact_byte_limit: int | None = None,
) -> DevelopmentDependencyClosure:
    """Recompute from supplied bytes only; no caller-supplied graph or closure assertion is trusted."""

    graph_limit = (
        min(LEGACY_DEPENDENCY_GRAPH_BYTES, MAX_DEPENDENCY_GRAPH_BYTES)
        if graph_artifact_byte_limit is None
        else graph_artifact_byte_limit
    )
    if type(graph_limit) is not int or not 1024 <= graph_limit <= MAX_DEPENDENCY_GRAPH_BYTES:
        raise ValueError("dependency graph artifact bound is invalid")
    if type(include_target_context) is not bool:
        raise ValueError("dependency target context requires an explicit boolean selection")
    if type(include_scoped_context) is not bool or (
        include_scoped_context and not include_target_context
    ):
        raise ValueError("scoped context requires an explicit boolean and target context")
    if type(include_call_context) is not bool or (
        include_call_context and not include_scoped_context
    ):
        raise ValueError("typed call context requires an explicit boolean and scoped context")
    if type(include_syntax_context) is not bool or (
        include_syntax_context and not include_call_context
    ):
        raise ValueError("syntax context requires an explicit boolean and typed call context")
    if type(source_files) is not tuple or not 1 <= len(source_files) <= MAX_DEPENDENCY_SOURCES:
        raise ValueError("dependency computation requires a bounded immutable source universe")
    if type(include_modifier_context) is not bool or (
        include_modifier_context and not include_syntax_context
    ):
        raise ValueError("modifier context requires an explicit boolean and syntax context")
    if type(include_constructor_context) is not bool or (
        include_constructor_context and not include_modifier_context
    ):
        raise ValueError("constructor context requires an explicit boolean and modifier context")
    if type(include_static_closure) is not bool or (
        include_static_closure and not include_constructor_context
    ):
        raise ValueError("static closure requires an explicit boolean and constructor context")
    if (
        type(remapping_text) is not str
        or len(remapping_text.encode()) > MAX_DEPENDENCY_REMAPPING_BYTES
        or detect_secrets(remapping_text)
    ):
        raise ValueError("dependency remappings are oversized or secret-like")
    inventory = []
    files = []
    total = 0
    for pair in source_files:
        if type(pair) is not tuple or len(pair) != 2:
            raise ValueError("dependency source pair differs")
        name, raw = pair
        if (
            type(name) is not str
            or is_sensitive_workspace_path(name)
            or re.fullmatch(_PATH, name) is None
            or len(name) > 512
            or type(raw) is not bytes
            or not 0 < len(raw) <= MAX_DEPENDENCY_FILE_BYTES
        ):
            raise ValueError("dependency source path or bytes are invalid")
        total += len(raw)
        if total > MAX_DEPENDENCY_BYTES:
            raise ValueError("dependency source universe exceeds the byte ceiling")
        content = raw.decode("utf-8", errors="strict")
        if (
            content.startswith("\ufeff")
            or any(ord(c) < 32 and c not in "\t\r\n" for c in content)
            or len(content.splitlines()) != len(raw.splitlines())
            or not 1 <= len(raw.splitlines()) <= 10_000
            or detect_secrets(content)
        ):
            raise ValueError("dependency source text is ambiguous or secret-like")
        digest = hashlib.sha256(raw).hexdigest()
        inventory.append(DependencySource(filename=name, sha256=digest, size=len(raw)))
        files.append(
            DiscoveredFile(
                Path(name), name, content, len(raw), len(raw.splitlines()), digest, "Solidity", ()
            )
        )
    ordered_paths = tuple(s.filename for s in inventory)
    if ordered_paths != tuple(sorted(ordered_paths)) or len(
        {p.casefold() for p in ordered_paths}
    ) != len(ordered_paths):
        raise ValueError("dependency sources must be sorted and case-distinct")
    rules, unsupported = _mapping_rules(remapping_text)
    imports: list[DependencyImport] = []
    gaps: list[DependencyParseGap] = []
    references: list[DependencyCandidateReference] = []
    paths = set(ordered_paths)
    for name, raw in source_files:
        found, shortfalls, candidates = _source_imports(name, raw, paths, rules)
        imports.extend(found)
        gaps.extend(shortfalls)
        references.extend(candidates)
        if any(
            len(population) > MAX_DEPENDENCY_RECORDS for population in (imports, gaps, references)
        ):
            raise ValueError("complete dependency imports/gaps exceed the record ceiling")
    discovery = DiscoveryResult(Path("."), tuple(files), (), frozenset(), None)
    # Empty artifact roots prohibit filesystem AST reads; fallback provenance remains explicit.
    source_index = build_solidity_index(discovery, [], [])
    graph = build_solidity_graphs(
        discovery,
        source_index,
        max_artifact_bytes=graph_limit,
    )
    facts = tuple(
        DependencyGraphFact(
            source=e.path,
            line_start=e.start_line,
            line_end=e.end_line,
            kind=e.graph,
            provenance=e.provenance,
            confidence=e.confidence,
            fact_sha256=canonical_sha256(e.model_dump(mode="json")),
            source_id=e.source_id,
            target_id=e.target_id,
        )
        for e in graph.edges
        if e.graph in (STATIC_CLOSURE_KINDS if include_static_closure else _CALL_KINDS)
    )
    if len(facts) > MAX_DEPENDENCY_RECORDS:
        raise ValueError("complete dependency graph projection exceeds its record ceiling")
    adjacency: dict[str, set[str]] = {p: set() for p in paths}
    bad = {g.source for g in gaps} | {i.source for i in imports if i.shortfall is not None}
    for edge in imports:
        if edge.target is not None:
            adjacency[edge.source].add(edge.target)
    primaries = []
    for primary in ordered_paths:
        visited: set[str] = set()
        pending = [primary]
        while pending:
            member = pending.pop()
            if member not in visited:
                visited.add(member)
                pending.extend(adjacency[member] - visited)
        primaries.append(
            DependencyPrimaryClosure(
                primary=primary,
                import_members=tuple(sorted(visited)),
                import_closure="NOT_ESTABLISHED"
                if unsupported or visited & bad
                else "IMPORT_CLOSED",
            )
        )
    values: dict[str, Any] = dict(
        source_inventory=tuple(inventory),
        source_inventory_sha256=canonical_sha256([s.model_dump(mode="json") for s in inventory]),
        remapping_text=remapping_text,
        remapping_sha256=hashlib.sha256(remapping_text.encode()).hexdigest(),
        unsupported_remapping_lines=unsupported,
        imports=tuple(imports),
        parse_gaps=tuple(gaps),
        candidate_references=tuple(references),
        graph_sha256=canonical_sha256(graph.model_dump(mode="json")),
        graph_generation_complete=graph.generation_complete,
        graph_artifact_byte_limit=graph.artifact_byte_limit,
        graph_edge_omissions=graph.edge_omissions,
        graph_fact_omissions=graph.fact_omissions,
        graph_warnings=tuple(graph.warnings),
        graph_edge_omission_sha256=canonical_sha256(
            [o.model_dump(mode="json") for o in graph.edge_omissions]
        ),
        graph_fact_omission_sha256=canonical_sha256(
            [o.model_dump(mode="json") for o in graph.fact_omissions]
        ),
        graph_warnings_sha256=canonical_sha256(graph.warnings),
        graph_facts=facts,
        primaries=tuple(primaries),
        dependency_closure="IMPORT_CLOSED"
        if all(p.import_closure == "IMPORT_CLOSED" for p in primaries)
        else "NOT_ESTABLISHED",
    )
    if include_target_context:
        values.update(
            schema_version="1.1",
            target_context=build_dependency_target_context(
                source_files=source_files,
                imports=tuple(imports),
                source_inventory_sha256=values["source_inventory_sha256"],
                parse_gaps=tuple(gaps),
                unsupported_remapping_lines=unsupported,
            ),
        )
    if include_scoped_context:
        values.update(
            schema_version="1.2",
            scoped_context=build_dependency_scoped_context(
                source_files=source_files,
                imports=tuple(imports),
                target_context=values["target_context"],
                include_modifiers=include_modifier_context,
                include_constructors=include_constructor_context,
            ),
        )
    if include_call_context:
        values.update(
            schema_version="1.3",
            call_context=build_dependency_call_context(
                source_files=source_files,
                imports=tuple(imports),
                target_context=values["target_context"],
                scoped_context=values["scoped_context"],
            ),
        )
    if include_syntax_context:
        values.update(
            schema_version="1.4",
            syntax_context=build_dependency_syntax_context(
                source_files=source_files,
                call_context=values["call_context"],
            ),
        )
    provisional = DevelopmentDependencyClosure.model_construct(**values, witness_sha256="0" * 64)
    if include_modifier_context:
        values["schema_version"] = "1.5"
        provisional = DevelopmentDependencyClosure.model_construct(
            **values, witness_sha256="0" * 64
        )
    if include_constructor_context:
        values["schema_version"] = "1.6"
        provisional = DevelopmentDependencyClosure.model_construct(
            **values, witness_sha256="0" * 64
        )
    if include_static_closure:
        proof = compute_static_call_closure(
            witness=provisional,
            source_files=source_files,
            source_index=source_index,
        )
        values.update(
            schema_version="1.7", static_call_closure=proof, dependency_closure=proof.call_closure
        )
        values["primaries"] = tuple(
            DependencyPrimaryClosure(
                **primary.model_dump(exclude={"call_closure", "call_shortfall", "call_members"}),
                call_closure=item.call_closure,
                call_members=item.members,
                call_shortfall=None
                if item.call_closure == "CALL_CLOSED"
                else "STATIC_CLOSURE_SHORTFALLS_RECORDED",
            )
            for primary, item in zip(primaries, proof.primaries, strict=True)
        )
        provisional = DevelopmentDependencyClosure.model_construct(
            **values, witness_sha256="0" * 64
        )
    values["witness_sha256"] = canonical_sha256(
        provisional.model_dump(mode="json", exclude={"witness_sha256"})
    )
    return DevelopmentDependencyClosure.model_validate(values)
