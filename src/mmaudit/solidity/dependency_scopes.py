"""Source-owned lexical values and nominal member context, never deployed dispatch proof.

This bounded adapter shares the existing dependency lexer and import namespace. Unsupported
declarations/scopes remain evidence; a name in a different function cannot shadow this one.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.solidity.dependency_targets import (
    MAX_TARGET_CONTEXT_BYTES,
    MAX_TARGET_RECORDS,
    MAX_TARGET_WORK,
    DependencyTargetContext,
    DependencyTargetGap,
    DependencyTypeBinding,
    _qualified,
    _qualified_before,
    _Record,
    _source_names,
    _unit,
)

if TYPE_CHECKING:
    from mmaudit.solidity.dependency_closure import DependencyImport

MAX_SCOPE_DEPTH = 32
_SHA = r"^[0-9a-f]{64}$"
_PATH = r"^(?:[A-Za-z0-9][A-Za-z0-9._-]*/)*[A-Za-z0-9][A-Za-z0-9._-]*\.sol$"
_NAME = r"^[A-Za-z_$][A-Za-z0-9_$]*$"
_BUILTIN = re.compile(
    r"(?:address(?:payable)?|bool|string|bytes(?:[1-9]|[12][0-9]|3[0-2])?|u?int(?:"
    + "|".join(str(width) for width in range(8, 257, 8))
    + r")?)\Z"
)
_VARIABLE_FLAGS = frozenset(
    {"memory", "storage", "calldata", "public", "private", "internal", "constant", "immutable"}
)
_FUNCTION_FLAGS = frozenset(
    {"public", "external", "private", "internal", "view", "pure", "payable", "virtual"}
)
_NON_DECLARATIONS = frozenset(
    {"return", "emit", "revert", "delete", "break", "continue", "throw", "new"}
)


class _Identified(_Record):
    id: str = Field(pattern=_SHA)
    source: str = Field(pattern=_PATH, max_length=512)
    source_sha256: str = Field(pattern=_SHA)
    owner_type_id: str = Field(pattern=_SHA)
    byte_start: int = Field(ge=0, lt=262_144)
    byte_end: int = Field(gt=0, le=262_144)

    @classmethod
    def create(cls, **values: Any) -> Self:
        return cls.model_validate({**values, "id": canonical_sha256(values)})

    @model_validator(mode="after")
    def exact_identity(self) -> Self:
        if self.byte_end <= self.byte_start or self.id != canonical_sha256(
            self.model_dump(mode="json", exclude={"id"})
        ):
            raise ValueError("scoped declaration identity differs from its exact source span")
        return self


class DependencyLexicalScope(_Identified):
    kind: Literal["CONTRACT", "FUNCTION", "BLOCK", "FOR"]
    parent_id: str | None = Field(pattern=_SHA)


class DependencyValueDeclaration(_Identified):
    scope_id: str = Field(pattern=_SHA)
    kind: Literal["STATE", "PARAMETER", "RETURN", "LOCAL"]
    name: str = Field(pattern=_NAME, max_length=512)
    name_byte_start: int = Field(ge=0, lt=262_144)
    visible_from: int = Field(ge=0, le=262_144)
    visibility: Literal["public", "private", "internal", "UNSPECIFIED"]
    value_type: DependencyTypeBinding


class DependencyFunctionDeclaration(_Identified):
    scope_id: str = Field(pattern=_SHA)
    kind: Literal["function", "constructor", "modifier", "fallback", "receive"]
    name: str = Field(pattern=_NAME, max_length=512)
    parameters: tuple[DependencyTypeBinding, ...] = Field(max_length=64)
    returns: tuple[DependencyTypeBinding, ...] = Field(max_length=64)
    visibility: Literal["public", "external", "private", "internal", "UNSPECIFIED"]
    body_byte_start: int | None = Field(ge=0, lt=262_144)
    body_byte_end: int | None = Field(gt=0, le=262_144)

    @model_validator(mode="after")
    def exact_body(self) -> Self:
        if (self.body_byte_start is None) != (self.body_byte_end is None) or (
            self.body_byte_start is not None
            and self.body_byte_end is not None
            and not self.byte_start <= self.body_byte_start < self.body_byte_end <= self.byte_end
        ):
            raise ValueError("function body does not belong to its source declaration")
        return self


class DependencyScopedCall(_Record):
    source: str = Field(pattern=_PATH, max_length=512)
    byte_start: int = Field(ge=0, lt=262_144)
    byte_end: int = Field(gt=0, le=262_144)
    scope_id: str | None = Field(pattern=_SHA)
    member: str = Field(pattern=_NAME, max_length=512)
    argument_count: int | None = Field(ge=0, le=64)
    receiver_form: Literal["VALUE", "TYPE_CAST", "TYPE_MEMBER", "THIS", "UNSUPPORTED"]
    receiver: DependencyTypeBinding
    receiver_value_ids: tuple[str, ...] = Field(max_length=MAX_TARGET_RECORDS)
    member_declaration_ids: tuple[str, ...] = Field(max_length=MAX_TARGET_RECORDS)
    implementation_ids: tuple[str, ...] = Field(max_length=MAX_TARGET_RECORDS)
    implementation_member_ids: tuple[str, ...] = Field(max_length=MAX_TARGET_RECORDS)
    shortfalls: tuple[str, ...] = Field(max_length=64)
    member_resolution: Literal["DECLARATIONS_BOUND", "NOT_ESTABLISHED"]

    @model_validator(mode="after")
    def honest_member_resolution(self) -> Self:
        if self.byte_end <= self.byte_start or self.receiver.source != self.source:
            raise ValueError("scoped call source span differs")
        for values in (
            self.receiver_value_ids,
            self.member_declaration_ids,
            self.implementation_ids,
            self.implementation_member_ids,
            self.shortfalls,
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError("scoped call populations must be sorted and unique")
        bound = (
            not self.shortfalls
            and self.receiver.target_id is not None
            and bool(self.member_declaration_ids)
        )
        if (self.member_resolution == "DECLARATIONS_BOUND") != bound:
            raise ValueError("scoped member claim differs from its binding shortfalls")
        return self


class DependencyScopedMembers(_Record):
    primary: str = Field(pattern=_PATH, max_length=512)
    members: tuple[str, ...] = Field(min_length=1, max_length=256)
    unresolved_call_indices: tuple[int, ...] = Field(max_length=MAX_TARGET_RECORDS)
    gap_indices: tuple[int, ...] = Field(max_length=MAX_TARGET_RECORDS)


class DependencyScopedContext(_Record):
    policy: Literal[
        "MODERN_LEXICAL_VALUES_AND_NOMINAL_MEMBERS_V1",
        "MODERN_LEXICAL_VALUES_AND_MODIFIER_HEADERS_V2",
        "MODERN_LEXICAL_VALUES_AND_CONSTRUCTOR_HEADERS_V3",
    ] = "MODERN_LEXICAL_VALUES_AND_NOMINAL_MEMBERS_V1"
    scope: Literal["SOURCE_DECLARATIONS_NOT_COMPLETE_TYPECHECK_OR_DEPLOYED_DISPATCH"] = (
        "SOURCE_DECLARATIONS_NOT_COMPLETE_TYPECHECK_OR_DEPLOYED_DISPATCH"
    )
    source_inventory_sha256: str = Field(pattern=_SHA)
    target_context_sha256: str = Field(pattern=_SHA)
    supplied_type_ids: tuple[str, ...] = Field(max_length=MAX_TARGET_RECORDS)
    scopes: tuple[DependencyLexicalScope, ...] = Field(max_length=MAX_TARGET_RECORDS)
    values: tuple[DependencyValueDeclaration, ...] = Field(max_length=MAX_TARGET_RECORDS)
    functions: tuple[DependencyFunctionDeclaration, ...] = Field(max_length=MAX_TARGET_RECORDS)
    calls: tuple[DependencyScopedCall, ...] = Field(max_length=MAX_TARGET_RECORDS)
    gaps: tuple[DependencyTargetGap, ...] = Field(max_length=MAX_TARGET_RECORDS)
    primaries: tuple[DependencyScopedMembers, ...] = Field(min_length=1, max_length=256)
    complete_static_resolution: Literal[False] = False

    @field_validator("complete_static_resolution", mode="before")
    @classmethod
    def no_complete_typecheck(cls, value: object) -> Literal[False]:
        if value is not False:
            raise ValueError("lexical member context is not a complete Solidity typecheck")
        return False

    @model_validator(mode="after")
    def exact_population(self) -> Self:
        paths = tuple(p.primary for p in self.primaries)
        types = set(self.supplied_type_ids)
        scopes = {s.id: s for s in self.scopes}
        values = {v.id: v for v in self.values}
        functions = {f.id: f for f in self.functions}
        if paths != tuple(sorted(set(paths))) or self.supplied_type_ids != tuple(sorted(types)):
            raise ValueError("scoped source/type universe must be exact and sorted")
        for records in (self.scopes, self.values, self.functions):
            if len({r.id for r in records}) != len(records) or any(
                r.source not in paths or r.owner_type_id not in types for r in records
            ):
                raise ValueError("scoped declaration leaves its source/type universe")
        for scope in self.scopes:
            if scope.kind == "CONTRACT":
                if scope.parent_id is not None:
                    raise ValueError("contract scope has an unexpected parent")
            else:
                parent = scopes.get(scope.parent_id or "")
                if parent is None or (
                    parent.source != scope.source
                    or parent.owner_type_id != scope.owner_type_id
                    or not parent.byte_start <= scope.byte_start < scope.byte_end <= parent.byte_end
                    or (parent.byte_start == scope.byte_start and parent.byte_end == scope.byte_end)
                ):
                    raise ValueError("lexical scope parent is missing, cyclic or out of range")
        for value in self.values:
            parent = scopes.get(value.scope_id)
            if parent is None or (
                value.source != parent.source
                or value.owner_type_id != parent.owner_type_id
                or not parent.byte_start <= value.byte_start < value.byte_end <= parent.byte_end
                or not value.byte_start <= value.name_byte_start < value.byte_end
                or not parent.byte_start <= value.visible_from <= parent.byte_end
                or value.value_type.source != value.source
                or not set(value.value_type.candidate_ids) <= types
            ):
                raise ValueError("value declaration leaves its lexical scope or type universe")
        for function in self.functions:
            parent = scopes.get(function.scope_id)
            if (
                parent is None
                or parent.kind != "FUNCTION"
                or (
                    function.source != parent.source
                    or function.owner_type_id != parent.owner_type_id
                    or (function.byte_start, function.byte_end)
                    != (parent.byte_start, parent.byte_end)
                    or any(
                        p.source != function.source or not set(p.candidate_ids) <= types
                        for p in (*function.parameters, *function.returns)
                    )
                )
            ):
                raise ValueError("function declaration leaves its exact lexical source scope")
        for call in self.calls:
            if (
                call.source not in paths
                or (call.scope_id is not None and call.scope_id not in scopes)
                or not set(call.receiver_value_ids) <= set(values)
                or not set((*call.member_declaration_ids, *call.implementation_member_ids))
                <= set(functions)
                or not set((*call.receiver.candidate_ids, *call.implementation_ids)) <= types
            ):
                raise ValueError("scoped call leaves its declaration universe")
        for primary in self.primaries:
            if (
                primary.members != tuple(sorted(set(primary.members)))
                or (
                    primary.primary not in primary.members or not set(primary.members) <= set(paths)
                )
                or primary.unresolved_call_indices
                != tuple(
                    i
                    for i, c in enumerate(self.calls)
                    if c.source in primary.members and c.member_resolution == "NOT_ESTABLISHED"
                )
                or primary.gap_indices
                != tuple(i for i, g in enumerate(self.gaps) if g.source in primary.members)
            ):
                raise ValueError("scoped primary membership or shortfall indices differ")
        if (
            any(g.source not in paths for g in self.gaps)
            or len(self.model_dump_json().encode()) > MAX_TARGET_CONTEXT_BYTES
        ):
            raise ValueError("complete scoped context exceeds its source or byte boundary")
        return self


class _Builder:
    def __init__(
        self,
        sources: tuple[tuple[str, bytes], ...],
        imports: tuple[DependencyImport, ...],
        context: DependencyTargetContext,
        *,
        include_modifiers: bool = False,
        include_constructors: bool = False,
    ) -> None:
        self.context = context
        self.include_modifiers = include_modifiers
        self.include_constructors = include_constructors
        self.base_arguments: dict[tuple[str, int], tuple[int, int, int, str]] = {}
        # Token anchors are the actual '(' or, for implicit applications, the first name token.
        # Values bind the name start/end-exclusive and the entire application end-inclusive.
        self.modifiers: dict[tuple[str, int], tuple[int, int, int]] = {}
        self.gaps = list(context.gaps)
        self.units = {p: _unit(p, raw, imports, self.gaps) for p, raw in sources}
        self.types = {d.id: d for d in context.declarations}
        self.names, self.unsafe_sources, self.work = _source_names(
            self.units, context.declarations, self.gaps
        )
        self.scopes: list[DependencyLexicalScope] = []
        self.values: list[DependencyValueDeclaration] = []
        self.functions: list[DependencyFunctionDeclaration] = []
        self.unsafe_scopes: set[str] = set()
        self.excluded = {p: set(u.excluded) for p, u in self.units.items()}
        self.ancestors: dict[str, set[str]] = {d: set() for d in self.types}
        for edge in context.inheritance:
            if edge.base.target_id is not None:
                self.ancestors[edge.inheritor_id].add(edge.base.target_id)
        for _ in self.types:
            changed = False
            for identity, ancestors in self.ancestors.items():
                self.charge(1 + len(ancestors))
                updated = set(ancestors)
                for ancestor in ancestors:
                    updated.update(self.ancestors[ancestor])
                if updated != ancestors:
                    self.ancestors[identity] = updated
                    changed = True
            if not changed:
                break

    def charge(self, amount: int = 1) -> None:
        self.work += amount
        if self.work > MAX_TARGET_WORK:
            raise ValueError("complete scoped resolution exceeds its work ceiling")

    def gap(self, source: str, offset: int, reason: str, scope: str | None = None) -> None:
        self.gaps.append(DependencyTargetGap(source=source, byte_start=offset, reason=reason))
        if scope is not None:
            self.unsafe_scopes.add(scope)
        if len(self.gaps) > MAX_TARGET_RECORDS:
            raise ValueError("complete scoped parse gaps exceed their record ceiling")

    def binding(self, source: str, offset: int, spelling: str) -> DependencyTypeBinding:
        candidates = tuple(sorted(self.names[source].get(spelling, ())))
        reason = (
            "UNSUPPORTED_SOURCE_NAMESPACE"
            if source in self.unsafe_sources
            else "NON_CONTRACT_VALUE_TYPE"
            if _BUILTIN.fullmatch(spelling)
            else "TYPE_NAME_NOT_RESOLVED"
            if not candidates
            else "AMBIGUOUS_TYPE_NAME"
            if len(candidates) != 1
            else None
        )
        return DependencyTypeBinding(
            source=source,
            byte_start=offset,
            spelling=spelling,
            candidate_ids=candidates,
            target_id=candidates[0] if reason is None else None,
            shortfall=reason,
        )

    def scope(
        self, owner: str, begin: int, end: int, kind: str, parent: str | None
    ) -> DependencyLexicalScope:
        declaration = self.types[owner]
        tokens = self.units[declaration.source].tokens
        scope = DependencyLexicalScope.create(
            source=declaration.source,
            source_sha256=declaration.source_sha256,
            owner_type_id=owner,
            byte_start=tokens[begin].start,
            byte_end=tokens[end].end,
            kind=kind,
            parent_id=parent,
        )
        self.scopes.append(scope)
        if len(self.scopes) > MAX_TARGET_RECORDS:
            raise ValueError("complete lexical scope population exceeds its ceiling")
        return scope

    def segments(self, source: str, begin: int, end: int, delimiter: str) -> list[tuple[int, int]]:
        unit = self.units[source]
        result: list[tuple[int, int]] = []
        first = cursor = begin
        while cursor < end:
            self.charge()
            token = unit.tokens[cursor]
            if token.value == delimiter:
                result.append((first, cursor))
                first = cursor + 1
            elif token.value in {"(", "[", "{"} and cursor in unit.pairs:
                cursor = unit.pairs[cursor]
            cursor += 1
        if first < end or result:
            result.append((first, end))
        return result

    def type_end(self, source: str, begin: int, end: int) -> int | None:
        unit = self.units[source]
        tokens = unit.tokens
        if (
            begin >= end
            or tokens[begin].kind != "identifier"
            or tokens[begin].value in _NON_DECLARATIONS
        ):
            return None
        cursor = begin + 1
        if tokens[begin].value in {"mapping", "function"}:
            if cursor >= end or tokens[cursor].value != "(" or cursor not in unit.pairs:
                return None
            cursor = unit.pairs[cursor] + 1
            if tokens[begin].value == "function":
                while cursor < end and tokens[cursor].value in _FUNCTION_FLAGS:
                    cursor += 1
                if cursor < end and tokens[cursor].value == "returns":
                    cursor += 1
                    if cursor not in unit.pairs or tokens[cursor].value != "(":
                        return None
                    cursor = unit.pairs[cursor] + 1
        else:
            while (
                cursor + 1 < end
                and tokens[cursor].value == "."
                and tokens[cursor + 1].kind == "identifier"
            ):
                cursor += 2
            if (
                tokens[begin].value == "address"
                and cursor < end
                and tokens[cursor].value == "payable"
            ):
                cursor += 1
        while cursor < end and tokens[cursor].value == "[":
            if cursor not in unit.pairs:
                return None
            cursor = unit.pairs[cursor] + 1
        return cursor if cursor <= end else None

    def variable(
        self,
        scope: DependencyLexicalScope,
        begin: int,
        end: int,
        kind: str,
        visible_from: int,
        *,
        unnamed: bool = False,
    ) -> DependencyTypeBinding | None:
        unit = self.units[scope.source]
        tokens = unit.tokens
        type_end = self.type_end(scope.source, begin, end)
        if type_end is None:
            return None
        spelling = "".join(t.value for t in tokens[begin:type_end])
        if len(spelling) > 512:
            raise ValueError("complete value type spelling exceeds its ceiling")
        binding = self.binding(scope.source, tokens[begin].start, spelling)
        cursor = type_end
        visibility = "UNSPECIFIED"
        while cursor < end and tokens[cursor].value in _VARIABLE_FLAGS | {"override"}:
            if tokens[cursor].value in {"public", "private", "internal"}:
                visibility = tokens[cursor].value
            if (
                tokens[cursor].value == "override"
                and cursor + 1 < end
                and tokens[cursor + 1].value == "("
            ):
                cursor = unit.pairs.get(cursor + 1, end) + 1
            else:
                cursor += 1
        if cursor == end and unnamed:
            return binding
        if cursor >= end or tokens[cursor].kind != "identifier":
            return None
        if cursor + 1 < end and tokens[cursor + 1].value != "=":
            return None
        value = DependencyValueDeclaration.create(
            source=scope.source,
            source_sha256=scope.source_sha256,
            owner_type_id=scope.owner_type_id,
            byte_start=tokens[begin].start,
            byte_end=tokens[end - 1].end,
            scope_id=scope.id,
            kind=kind,
            name=tokens[cursor].value,
            name_byte_start=tokens[cursor].start,
            visible_from=visible_from,
            visibility=visibility,
            value_type=binding.model_dump(mode="python"),
        )
        self.values.append(value)
        if len(self.values) > MAX_TARGET_RECORDS:
            raise ValueError("complete scoped value population exceeds its ceiling")
        return binding

    def parameters(
        self,
        scope: DependencyLexicalScope,
        opening: int,
        closing: int,
        kind: str,
        visible_from: int,
    ) -> tuple[DependencyTypeBinding, ...]:
        found: list[DependencyTypeBinding] = []
        for begin, end in self.segments(scope.source, opening + 1, closing, ","):
            if len(found) >= 64:
                raise ValueError("complete function parameter population exceeds its ceiling")
            binding = self.variable(scope, begin, end, kind, visible_from, unnamed=True)
            if binding is None:
                self.gap(
                    scope.source,
                    self.units[scope.source].tokens[begin].start,
                    "UNSUPPORTED_PARAMETER_DECLARATION",
                    scope.id,
                )
                binding = self.binding(
                    scope.source,
                    self.units[scope.source].tokens[begin].start,
                    "UNSUPPORTED_PARAMETER",
                )
            found.append(binding)
        return tuple(found)

    def statement_end(self, source: str, begin: int, limit: int, depth: int = 0) -> int:
        if depth > MAX_SCOPE_DEPTH:
            raise ValueError("complete statement scope exceeds its depth ceiling")
        unit = self.units[source]
        tokens = unit.tokens
        if begin >= limit:
            return limit
        cursor = begin
        if tokens[cursor].value == "{" and cursor in unit.pairs:
            return min(unit.pairs[cursor] + 1, limit)
        if tokens[cursor].value in {"if", "while", "for"}:
            opening = cursor + 1
            if opening in unit.pairs and tokens[opening].value == "(":
                end = self.statement_end(source, unit.pairs[opening] + 1, limit, depth + 1)
                if tokens[cursor].value == "if" and end < limit and tokens[end].value == "else":
                    end = self.statement_end(source, end + 1, limit, depth + 1)
                return end
        while cursor < limit:
            self.charge()
            if tokens[cursor].value == ";":
                return cursor + 1
            if tokens[cursor].value in {"(", "[", "{"} and cursor in unit.pairs:
                cursor = unit.pairs[cursor]
            cursor += 1
        return limit

    def walk(self, scope: DependencyLexicalScope, begin: int, end: int, depth: int = 0) -> None:
        if depth > MAX_SCOPE_DEPTH:
            raise ValueError("complete lexical scope exceeds its depth ceiling")
        unit = self.units[scope.source]
        tokens = unit.tokens
        cursor = begin
        while cursor < end:
            self.charge()
            first = cursor
            token = tokens[cursor]
            if token.value == "{" and cursor in unit.pairs:
                close = unit.pairs[cursor]
                child = self.scope(scope.owner_type_id, cursor, close, "BLOCK", scope.id)
                self.walk(child, cursor + 1, close, depth + 1)
                cursor = close + 1
                continue
            if token.value == "unchecked" and cursor + 1 < end and tokens[cursor + 1].value == "{":
                cursor += 1
                continue
            if (
                token.value in {"if", "while", "for"}
                and cursor + 1 in unit.pairs
                and tokens[cursor + 1].value == "("
            ):
                close = unit.pairs[cursor + 1]
                body_end = self.statement_end(scope.source, close + 1, end, depth + 1)
                target_scope = scope
                if token.value == "for":
                    target_scope = self.scope(
                        scope.owner_type_id, cursor, body_end - 1, "FOR", scope.id
                    )
                    parts = self.segments(scope.source, cursor + 2, close, ";")
                    if len(parts) != 3:
                        self.gap(
                            scope.source, token.start, "UNSUPPORTED_FOR_HEADER", target_scope.id
                        )
                    elif parts[0][0] < parts[0][1]:
                        a, b = parts[0]
                        self.variable(target_scope, a, b, "LOCAL", tokens[b].end)
                if close + 1 < body_end and tokens[close + 1].value != "{":
                    target_scope = self.scope(
                        scope.owner_type_id, close + 1, body_end - 1, "BLOCK", target_scope.id
                    )
                self.walk(target_scope, close + 1, body_end, depth + 1)
                cursor = body_end
                if token.value == "if" and cursor < end and tokens[cursor].value == "else":
                    other_end = self.statement_end(scope.source, cursor + 1, end, depth + 1)
                    other_scope = scope
                    if cursor + 1 < other_end and tokens[cursor + 1].value != "{":
                        other_scope = self.scope(
                            scope.owner_type_id, cursor + 1, other_end - 1, "BLOCK", scope.id
                        )
                    self.walk(other_scope, cursor + 1, other_end, depth + 1)
                    cursor = other_end
                continue
            cursor = self.statement_end(scope.source, first, end, depth + 1)
            if cursor <= first:
                raise ValueError("scoped statement parser did not advance")
            if token.value in {"assembly", "try", "catch", "do"}:
                self.gap(scope.source, token.start, "UNSUPPORTED_LEXICAL_REGION", scope.id)
            elif token.value == "(" and any(t.value == "=" for t in tokens[first:cursor]):
                self.gap(scope.source, token.start, "UNSUPPORTED_TUPLE_DECLARATION", scope.id)
            elif tokens[cursor - 1].value != ";":
                self.gap(
                    scope.source, token.start, "UNTERMINATED_OR_UNSUPPORTED_STATEMENT", scope.id
                )
            else:
                self.variable(scope, first, cursor - 1, "LOCAL", tokens[cursor - 1].end)

    def function(self, parent: DependencyLexicalScope, begin: int, limit: int) -> int:
        unit = self.units[parent.source]
        tokens = unit.tokens
        kind = tokens[begin].value
        cursor = begin + 1
        name = kind
        if kind in {"function", "modifier"}:
            if cursor >= limit or tokens[cursor].kind != "identifier":
                self.gap(
                    parent.source, tokens[begin].start, "UNSUPPORTED_FUNCTION_HEADER", parent.id
                )
                return self.statement_end(parent.source, begin, limit)
            name = tokens[cursor].value
            cursor += 1
        bare_modifier = (
            self.include_modifiers
            and kind == "modifier"
            and (cursor < limit and tokens[cursor].value != "(")
        )
        if not bare_modifier and (cursor not in unit.pairs or tokens[cursor].value != "("):
            self.gap(
                parent.source, tokens[begin].start, "UNSUPPORTED_FUNCTION_PARAMETERS", parent.id
            )
            return self.statement_end(parent.source, begin, limit)
        opening = cursor
        closing = cursor - 1 if bare_modifier else unit.pairs[cursor]
        cursor = closing + 1
        returns: tuple[int, int] | None = None
        visibility = "UNSPECIFIED"
        unsupported = False
        applications: list[tuple[int, int, int, int]] = []
        while cursor < limit and tokens[cursor].value not in {"{", ";"}:
            self.charge()
            word = tokens[cursor].value
            if word in {"public", "external", "private", "internal"}:
                visibility = word
            elif word == "returns" and cursor + 1 in unit.pairs and tokens[cursor + 1].value == "(":
                returns = (cursor + 1, unit.pairs[cursor + 1])
                cursor = returns[1]
            elif word == "override":
                if cursor + 1 < limit and tokens[cursor + 1].value == "(":
                    cursor = unit.pairs.get(cursor + 1, limit)
            elif word not in _FUNCTION_FLAGS:
                if (
                    self.include_modifiers
                    and kind != "modifier"
                    and tokens[cursor].kind == "identifier"
                ):
                    first = cursor
                    while (
                        cursor + 2 < limit
                        and tokens[cursor + 1].value == "."
                        and tokens[cursor + 2].kind == "identifier"
                    ):
                        self.charge()
                        cursor += 2
                    name_end = cursor + 1
                    anchor = first
                    if name_end < limit and tokens[name_end].value == "(":
                        if name_end not in unit.pairs:
                            unsupported = True
                            break
                        anchor = name_end
                        cursor = unit.pairs[name_end]
                    applications.append((first, name_end, anchor, cursor))
                    if len(applications) + len(self.modifiers) > MAX_TARGET_RECORDS:
                        raise ValueError("complete modifier population exceeds its ceiling")
                else:
                    unsupported = True
                    if cursor + 1 < limit and tokens[cursor + 1].value == "(":
                        cursor = unit.pairs.get(cursor + 1, limit)
            cursor += 1
        if cursor >= limit or (tokens[cursor].value == "{" and cursor not in unit.pairs):
            self.gap(parent.source, tokens[begin].start, "FUNCTION_BODY_NOT_PARSED", parent.id)
            return limit
        body = cursor if tokens[cursor].value == "{" else None
        last = unit.pairs[cursor] if body is not None else cursor
        scope = self.scope(parent.owner_type_id, begin, last, "FUNCTION", parent.id)
        visible = tokens[cursor].end
        parameters = (
            ()
            if bare_modifier
            else self.parameters(
                scope,
                opening,
                closing,
                "PARAMETER",
                tokens[closing].end if self.include_modifiers else visible,
            )
        )
        return_types = self.parameters(scope, *returns, "RETURN", visible) if returns else ()
        function = DependencyFunctionDeclaration.create(
            source=parent.source,
            source_sha256=parent.source_sha256,
            owner_type_id=parent.owner_type_id,
            byte_start=tokens[begin].start,
            byte_end=tokens[last].end,
            scope_id=scope.id,
            kind=kind,
            name=name,
            parameters=tuple(p.model_dump(mode="python") for p in parameters),
            returns=tuple(p.model_dump(mode="python") for p in return_types),
            visibility=visibility,
            body_byte_start=tokens[body].start if body is not None else None,
            body_byte_end=tokens[last].end if body is not None else None,
        )
        self.functions.append(function)
        if len(self.functions) > MAX_TARGET_RECORDS:
            raise ValueError("complete function member population exceeds its ceiling")
        self.excluded[parent.source].update(range(begin, cursor + 1))
        for first, name_end, anchor, end in applications:
            self.modifiers[parent.source, anchor] = (first, name_end, end)
            self.excluded[parent.source].difference_update(range(first, end + 1))
        if unsupported:
            self.gap(
                parent.source,
                tokens[begin].start,
                "FUNCTION_MODIFIER_OR_HEADER_UNRESOLVED",
                scope.id,
            )
        if body is not None:
            self.walk(scope, body + 1, last)
        return last + 1

    def parse(self) -> None:
        for source, unit in self.units.items():
            tokens = unit.tokens
            # Pre-0.5 function-wide declaration scope must never receive modern block bindings.
            scope_pragma_seen = False
            for i, token in enumerate(tokens):
                if (
                    token.value == "pragma"
                    and i + 1 < len(tokens)
                    and tokens[i + 1].value == "solidity"
                ):
                    scope_pragma_seen = True
                    end = next(
                        (j for j in range(i + 2, len(tokens)) if tokens[j].value == ";"),
                        len(tokens),
                    )
                    version = "".join(t.value for t in tokens[i + 2 : end])
                    if not re.fullmatch(r"\^?0\.[5-8]\.[0-9]+", version):
                        self.unsafe_sources.add(source)
                        self.gap(source, token.start, "SCOPE_LANGUAGE_VERSION_NOT_ESTABLISHED")
            if not scope_pragma_seen:
                self.unsafe_sources.add(source)
                self.gap(source, 0, "SCOPE_LANGUAGE_VERSION_NOT_ESTABLISHED")
            end_tokens = {token.end: i for i, token in enumerate(tokens)}
            for declaration in unit.declarations:
                end = end_tokens[declaration.byte_end]
                opening = unit.pairs[end]
                begin = opening
                if self.include_constructors:
                    begin = next(
                        i for i, token in enumerate(tokens) if token.start == declaration.byte_start
                    )
                parent = self.scope(declaration.id, begin, end, "CONTRACT", None)
                if self.include_constructors:
                    starts = {token.start: i for i, token in enumerate(tokens)}
                    for owner, offset, _spelling in unit.bases:
                        if owner != declaration.id:
                            continue
                        first = starts[offset]
                        name_end = first + 1
                        while name_end + 1 < opening and tokens[name_end].value == ".":
                            self.charge()
                            name_end += 2
                        if (
                            name_end < opening
                            and tokens[name_end].value == "("
                            and name_end in unit.pairs
                        ):
                            last = unit.pairs[name_end]
                            self.base_arguments[source, name_end] = (first, name_end, last, owner)
                            self.excluded[source].difference_update(range(first, last + 1))
                            if len(self.base_arguments) > MAX_TARGET_RECORDS:
                                raise ValueError(
                                    "complete base-constructor population exceeds its ceiling"
                                )
                cursor = opening + 1
                while cursor < end:
                    self.charge()
                    token = tokens[cursor]
                    if token.value in {
                        "function",
                        "constructor",
                        "modifier",
                        "fallback",
                        "receive",
                    }:
                        # A function-typed state variable is not a function declaration.
                        if (
                            token.value == "function"
                            and cursor + 1 < end
                            and tokens[cursor + 1].value == "("
                        ):
                            last = self.statement_end(source, cursor, end)
                            if (
                                tokens[last - 1].value != ";"
                                or self.variable(
                                    parent, cursor, last - 1, "STATE", parent.byte_start
                                )
                                is None
                            ):
                                self.gap(
                                    source, token.start, "UNSUPPORTED_STATE_DECLARATION", parent.id
                                )
                            cursor = last
                        else:
                            cursor = self.function(parent, cursor, end)
                        continue
                    if token.value in {"struct", "enum"}:
                        close = next(
                            (j for j in range(cursor + 1, end) if tokens[j].value in {"{", ";"}),
                            end,
                        )
                        last = unit.pairs.get(close, close) + 1
                        self.gap(
                            source, token.start, "NESTED_TYPE_DECLARATION_UNSUPPORTED", parent.id
                        )
                    else:
                        last = self.statement_end(source, cursor, end)
                        if tokens[last - 1].value != ";":
                            self.gap(source, token.start, "UNSUPPORTED_CONTRACT_MEMBER", parent.id)
                        elif token.value in {"event", "error"}:
                            self.excluded[source].update(range(cursor, last))
                        elif (
                            self.variable(parent, cursor, last - 1, "STATE", parent.byte_start)
                            is None
                        ):
                            self.gap(source, token.start, "UNSUPPORTED_CONTRACT_MEMBER", parent.id)
                    cursor = max(cursor + 1, last)

    def at_scope(self, source: str, offset: int) -> DependencyLexicalScope | None:
        self.charge(len(self.scopes))
        found = [
            s for s in self.scopes if s.source == source and s.byte_start <= offset < s.byte_end
        ]
        return min(found, key=lambda s: s.byte_end - s.byte_start) if found else None

    def lookup(
        self, scope: DependencyLexicalScope | None, offset: int, name: str
    ) -> tuple[DependencyValueDeclaration, ...]:
        if scope is None:
            return ()
        by_id = {s.id: s for s in self.scopes}
        cursor: DependencyLexicalScope | None = scope
        while cursor is not None:
            self.charge(len(self.values))
            found = tuple(
                v
                for v in self.values
                if v.scope_id == cursor.id and v.name == name and v.visible_from <= offset
            )
            if found:
                return found
            cursor = by_id.get(cursor.parent_id or "")
        self.charge(len(self.values))
        return tuple(
            v
            for v in self.values
            if v.kind == "STATE"
            and v.name == name
            and v.visibility != "private"
            and v.owner_type_id in self.ancestors[scope.owner_type_id]
        )

    def unsafe(self, scope: DependencyLexicalScope | None) -> bool:
        by_id = {s.id: s for s in self.scopes}
        while scope is not None:
            if scope.id in self.unsafe_scopes or scope.source in self.unsafe_sources:
                return True
            scope = by_id.get(scope.parent_id or "")
        return False

    def shadowed(self, scope: DependencyLexicalScope | None, offset: int, name: str) -> bool:
        if self.lookup(scope, offset, name):
            return True
        if scope is None:
            return False
        self.charge(len(self.functions))
        owners = {scope.owner_type_id} | self.ancestors[scope.owner_type_id]
        return any(f.owner_type_id in owners and f.name == name for f in self.functions)

    @staticmethod
    def type_signature(bindings: tuple[DependencyTypeBinding, ...]) -> tuple[str, ...]:
        return tuple(
            p.target_id or {"uint": "uint256", "int": "int256"}.get(p.spelling, p.spelling)
            for p in bindings
        )

    def resolve_declared_types(self) -> None:
        # Look up types after all declarations exist; later state/member declarations can
        # shadow an imported name, whereas later locals and sibling parameters cannot.
        scopes = {s.id: s for s in self.scopes}

        def resolve(scope_id: str, previous: DependencyTypeBinding) -> DependencyTypeBinding:
            scope = scopes[scope_id]
            binding = self.binding(previous.source, previous.byte_start, previous.spelling)
            if binding.candidate_ids and self.shadowed(
                scope, previous.byte_start, previous.spelling.split(".")[0]
            ):
                binding = binding.model_copy(
                    update={"target_id": None, "shortfall": "LEXICAL_TYPE_NAME_SHADOWED"}
                )
            return binding

        values = []
        for value in self.values:
            binding = resolve(value.scope_id, value.value_type)
            values.append(
                DependencyValueDeclaration.create(
                    **{
                        **value.model_dump(mode="python", exclude={"id"}),
                        "value_type": binding.model_dump(mode="python"),
                    }
                )
            )
        self.values = values
        functions = []
        for function in self.functions:
            functions.append(
                DependencyFunctionDeclaration.create(
                    **{
                        **function.model_dump(mode="python", exclude={"id"}),
                        "parameters": tuple(
                            resolve(function.scope_id, p).model_dump(mode="python")
                            for p in function.parameters
                        ),
                        "returns": tuple(
                            resolve(function.scope_id, p).model_dump(mode="python")
                            for p in function.returns
                        ),
                    }
                )
            )
        self.functions = functions

    @staticmethod
    def signature(function: DependencyFunctionDeclaration) -> tuple[str, ...]:
        return _Builder.type_signature(function.parameters)

    def members(
        self,
        owner: str,
        name: str,
        arity: int | None,
        kind: Literal["function", "modifier"] = "function",
    ) -> tuple[DependencyFunctionDeclaration, ...]:
        owners = {owner} | self.ancestors[owner]
        self.charge(len(self.functions))
        found = [
            f
            for f in self.functions
            if f.owner_type_id in owners
            and f.name == name
            and f.kind == kind
            and (arity is None or len(f.parameters) == arity)
        ]
        result = []
        for function in found:
            self.charge(len(found))
            if not any(
                function.owner_type_id != other.owner_type_id
                and function.owner_type_id in self.ancestors[other.owner_type_id]
                and self.signature(function) == self.signature(other)
                for other in found
            ):
                result.append(function)
        return tuple(result)

    def calls(self) -> tuple[DependencyScopedCall, ...]:
        calls = []
        for source, unit in self.units.items():
            tokens = unit.tokens
            for i, token in enumerate(tokens):
                self.charge()
                if (
                    i in self.excluded[source]
                    or token.kind != "punctuation"
                    or token.value != "."
                    or i + 2 >= len(tokens)
                    or tokens[i + 1].kind != "identifier"
                    or tokens[i + 2].value not in {"(", "{"}
                ):
                    continue
                scope = self.at_scope(source, token.start)
                _, conversion = _qualified_before(tokens, i + 2)
                if (
                    conversion in self.names[source]
                    and len(self.names[source][conversion]) == 1
                    and not self.shadowed(scope, token.start, (conversion or "").split(".")[0])
                ):
                    continue  # Namespace-qualified explicit type conversion, not member dispatch.
                first, spelling = _qualified_before(tokens, i)
                form = "TYPE_MEMBER"
                receiver_values: tuple[DependencyValueDeclaration, ...] = ()
                shortfalls: list[str] = []
                if i and tokens[i - 1].value == ")":
                    opening = unit.pairs.get(i - 1)
                    if opening is not None:
                        first, spelling = _qualified_before(tokens, opening)
                        form = "TYPE_CAST"
                        if spelling is None or spelling in _NON_DECLARATIONS:
                            spelling = _qualified(tokens[opening + 1 : i - 1])
                            first, form = opening, "VALUE"
                if spelling is None:
                    spelling, first, form = "UNSUPPORTED_RECEIVER", i, "UNSUPPORTED"
                if first and tokens[first - 1].value == "new":
                    shortfalls.append("CONTRACT_CREATION_TARGET_UNRESOLVED")
                if scope is not None and spelling == "this" and form == "TYPE_MEMBER":
                    form = "THIS"
                    receiver = DependencyTypeBinding(
                        source=source,
                        byte_start=tokens[first].start,
                        spelling=spelling,
                        candidate_ids=(scope.owner_type_id,),
                        target_id=scope.owner_type_id,
                        shortfall=None,
                    )
                else:
                    receiver_values = self.lookup(scope, token.start, spelling)
                    if receiver_values and form in {"TYPE_MEMBER", "VALUE"}:
                        form = "VALUE"
                        ids = tuple(
                            sorted({i for v in receiver_values for i in v.value_type.candidate_ids})
                        )
                        reason = (
                            "AMBIGUOUS_VALUE_DECLARATION"
                            if len(receiver_values) != 1
                            else receiver_values[0].value_type.shortfall
                        )
                        receiver = DependencyTypeBinding(
                            source=source,
                            byte_start=tokens[first].start,
                            spelling=spelling,
                            candidate_ids=ids,
                            target_id=ids[0] if reason is None and len(ids) == 1 else None,
                            shortfall=reason,
                        )
                    else:
                        receiver = self.binding(source, tokens[first].start, spelling)
                        if self.shadowed(scope, token.start, spelling.split(".")[0]):
                            receiver = receiver.model_copy(
                                update={
                                    "target_id": None,
                                    "shortfall": "LEXICAL_TYPE_NAME_SHADOWED",
                                }
                            )
                if receiver.shortfall is not None:
                    shortfalls.append(receiver.shortfall)
                if scope is None or self.unsafe(scope):
                    shortfalls.append("LEXICAL_SCOPE_NOT_ESTABLISHED")
                opening = i + 2
                if tokens[opening].value == "{" and opening in unit.pairs:
                    shortfalls.append("CALL_OPTIONS_NOT_RESOLVED")
                    opening = unit.pairs[opening] + 1
                count = None
                last = i + 2
                if opening < len(tokens) and tokens[opening].value == "(" and opening in unit.pairs:
                    last = unit.pairs[opening]
                    args = self.segments(source, opening + 1, last, ",")
                    if len(args) > 64:
                        raise ValueError("complete call argument population exceeds its ceiling")
                    if any(a == b for a, b in args) or (
                        opening + 1 < last and tokens[opening + 1].value == "{"
                    ):
                        shortfalls.append("CALL_ARGUMENT_FORM_UNRESOLVED")
                    else:
                        count = len(args)
                else:
                    shortfalls.append("CALL_ARGUMENTS_NOT_PARSED")
                member = tokens[i + 1].value
                members: dict[str, DependencyFunctionDeclaration] = {}
                implementations: set[str] = set()
                bodies: dict[str, DependencyFunctionDeclaration] = {}
                for target in receiver.candidate_ids:
                    for function in self.members(target, member, count):
                        members[function.id] = function
                    self.charge(len(self.types))
                    implementations.update(
                        d.id
                        for d in self.types.values()
                        if d.kind != "interface"
                        and (d.id == target or target in self.ancestors[d.id])
                    )
                if not members:
                    shortfalls.append("MEMBER_DECLARATION_NOT_RESOLVED")
                elif len(members) != 1:
                    shortfalls.append("OVERLOAD_OR_INHERITED_MEMBER_AMBIGUITY")
                if form == "TYPE_MEMBER" and any(
                    self.types[i].kind != "library" for i in receiver.candidate_ids
                ):
                    shortfalls.append("EXPLICIT_CONTRACT_MEMBER_DISPATCH_UNRESOLVED")
                if any(
                    f.visibility == "private"
                    and (scope is None or f.owner_type_id != scope.owner_type_id)
                    for f in members.values()
                ):
                    shortfalls.append("MEMBER_VISIBILITY_NOT_ESTABLISHED")
                if form != "TYPE_MEMBER" and any(
                    f.visibility not in {"public", "external"} for f in members.values()
                ):
                    shortfalls.append("MEMBER_EXTERNAL_VISIBILITY_NOT_ESTABLISHED")
                if any(
                    p.shortfall not in {None, "NON_CONTRACT_VALUE_TYPE"}
                    for f in members.values()
                    for p in f.parameters
                ):
                    shortfalls.append("MEMBER_PARAMETER_TYPE_UNRESOLVED")
                if receiver.candidate_ids and not implementations:
                    shortfalls.append("NO_SUPPLIED_IMPLEMENTER")
                for implementation in implementations:
                    selected = self.members(implementation, member, count)
                    body_matches = [
                        f
                        for f in selected
                        if f.body_byte_start is not None
                        and any(self.signature(f) == self.signature(m) for m in members.values())
                    ]
                    bodies.update((f.id, f) for f in body_matches)
                    if len(body_matches) != 1:
                        shortfalls.append("IMPLEMENTATION_MEMBER_BODY_NOT_UNIQUE")
                    if any(
                        not any(
                            self.type_signature(f.returns) == self.type_signature(m.returns)
                            for m in members.values()
                        )
                        or (form != "TYPE_MEMBER" and f.visibility not in {"public", "external"})
                        for f in body_matches
                    ):
                        shortfalls.append("IMPLEMENTATION_SIGNATURE_OR_VISIBILITY_MISMATCH")
                if self.gaps and receiver.candidate_ids:
                    shortfalls.append("IMPLEMENTATION_NAMESPACE_OR_PARSE_GAPS")
                shortfalls = sorted(set(shortfalls))
                calls.append(
                    DependencyScopedCall.model_validate(
                        dict(
                            source=source,
                            byte_start=tokens[first].start,
                            byte_end=tokens[last].end,
                            scope_id=scope.id if scope else None,
                            member=member,
                            argument_count=count,
                            receiver_form=form,
                            receiver=receiver,
                            receiver_value_ids=tuple(sorted(v.id for v in receiver_values)),
                            member_declaration_ids=tuple(sorted(members)),
                            implementation_ids=tuple(sorted(implementations)),
                            implementation_member_ids=tuple(sorted(bodies)),
                            shortfalls=tuple(shortfalls),
                            member_resolution="NOT_ESTABLISHED"
                            if shortfalls
                            else "DECLARATIONS_BOUND",
                        )
                    )
                )
                if len(calls) > MAX_TARGET_RECORDS:
                    raise ValueError("complete scoped call population exceeds its ceiling")
        return tuple(calls)


def build_dependency_scoped_context(
    *,
    source_files: tuple[tuple[str, bytes], ...],
    imports: tuple[DependencyImport, ...],
    target_context: DependencyTargetContext,
    include_modifiers: bool = False,
    include_constructors: bool = False,
) -> DependencyScopedContext:
    """Bind exact local declarations after source validation; runtime consumers recompute all."""

    if type(include_modifiers) is not bool:
        raise ValueError("modifier context requires an explicit boolean selection")
    if type(include_constructors) is not bool or (include_constructors and not include_modifiers):
        raise ValueError("constructor context requires an explicit boolean and modifier context")
    if type(target_context) is not DependencyTargetContext or tuple(
        p for p, _ in source_files
    ) != tuple(p.primary for p in target_context.primaries):
        raise ValueError("scoped context must use its exact validated target/source universe")
    builder = _Builder(
        source_files,
        imports,
        target_context,
        include_modifiers=include_modifiers,
        include_constructors=include_constructors,
    )
    builder.parse()
    builder.resolve_declared_types()
    calls = builder.calls()
    gaps = tuple(sorted(set(builder.gaps), key=lambda g: (g.source, g.byte_start, g.reason)))
    functions = {f.id: f for f in builder.functions}
    adjacency = {p.primary: set(p.members) for p in target_context.primaries}
    for call in calls:
        adjacency[call.source].update(
            builder.types[i].source
            for i in (*call.receiver.candidate_ids, *call.implementation_ids)
        )
        adjacency[call.source].update(
            functions[i].source
            for i in (*call.member_declaration_ids, *call.implementation_member_ids)
        )
    primaries = []
    for primary in adjacency:
        members: set[str] = set()
        pending = [primary]
        while pending:
            builder.charge()
            member = pending.pop()
            if member not in members:
                members.add(member)
                pending.extend(adjacency[member] - members)
        primaries.append(
            DependencyScopedMembers(
                primary=primary,
                members=tuple(sorted(members)),
                unresolved_call_indices=tuple(
                    i
                    for i, c in enumerate(calls)
                    if c.source in members and c.member_resolution == "NOT_ESTABLISHED"
                ),
                gap_indices=tuple(i for i, g in enumerate(gaps) if g.source in members),
            )
        )
    return DependencyScopedContext(
        policy="MODERN_LEXICAL_VALUES_AND_CONSTRUCTOR_HEADERS_V3"
        if include_constructors
        else "MODERN_LEXICAL_VALUES_AND_MODIFIER_HEADERS_V2"
        if include_modifiers
        else "MODERN_LEXICAL_VALUES_AND_NOMINAL_MEMBERS_V1",
        source_inventory_sha256=target_context.source_inventory_sha256,
        target_context_sha256=canonical_sha256(target_context.model_dump(mode="json")),
        supplied_type_ids=tuple(sorted(builder.types)),
        scopes=tuple(builder.scopes),
        values=tuple(builder.values),
        functions=tuple(builder.functions),
        calls=calls,
        gaps=gaps,
        primaries=tuple(primaries),
    )
