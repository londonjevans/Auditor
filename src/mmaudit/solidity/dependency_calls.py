"""Bounded source argument/return resolution; not compiler validity or deployed dispatch.

Every lexical call candidate is retained, including unsupported forms. A unique arity match
is insufficient: argument conversions and each nominal implementation signature must agree.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import (
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.solidity.dependency_scopes import (
    _BUILTIN,
    DependencyFunctionDeclaration,
    DependencyScopedContext,
    _Builder,
)
from mmaudit.solidity.dependency_targets import (
    MAX_TARGET_CONTEXT_BYTES,
    MAX_TARGET_RECORDS,
    DependencyTargetContext,
    DependencyTargetGap,
    DependencyTypeBinding,
    _qualified,
    _Record,
)

if TYPE_CHECKING:
    from mmaudit.solidity.dependency_closure import DependencyImport

MAX_EXPRESSION_DEPTH = 32
_SHA = r"^[0-9a-f]{64}$"
_PATH = r"^(?:[A-Za-z0-9][A-Za-z0-9._-]*/)*[A-Za-z0-9][A-Za-z0-9._-]*\.sol$"
_NON_CALLS = frozenset(
    {"if", "while", "for", "return", "returns", "catch", "mapping", "function", "unchecked"}
)
_PRECEDENCE = {
    "||": 1,
    "&&": 2,
    "==": 3,
    "!=": 3,
    "<": 4,
    ">": 4,
    "<=": 4,
    ">=": 4,
    "|": 5,
    "^": 6,
    "&": 7,
    "<<": 8,
    ">>": 8,
    "+": 9,
    "-": 9,
    "*": 10,
    "/": 10,
    "%": 10,
    "**": 11,
}


class DependencyExpressionType(_Record):
    kind: Literal["BUILTIN", "NOMINAL", "INTEGER_LITERAL", "STRING_LITERAL", "UNKNOWN"]
    spelling: str = Field(min_length=1, max_length=512)
    target_id: str | None = Field(default=None, pattern=_SHA)
    integer_value: str | None = Field(default=None, pattern=r"^-?(?:0|[1-9][0-9]*)$", max_length=79)
    shortfall: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def exact_type_shape(self) -> Self:
        if (self.kind == "NOMINAL") != (self.target_id is not None):
            raise ValueError("expression nominal identity differs")
        if (self.kind == "INTEGER_LITERAL") != (self.integer_value is not None):
            raise ValueError("expression integer identity differs")
        if (self.kind == "UNKNOWN") != (self.shortfall is not None):
            raise ValueError("expression type shortfall differs")
        if self.kind == "BUILTIN" and (
            not _BUILTIN.fullmatch(self.spelling) or self.spelling in {"uint", "int"}
        ):
            raise ValueError("expression builtin type is not canonical")
        if self.integer_value is not None and not -(2**255) <= int(self.integer_value) < 2**256:
            raise ValueError("expression integer literal exceeds its bounded domain")
        return self


class DependencyArgumentExpression(_Record):
    byte_start: int = Field(ge=0, lt=262_144)
    byte_end: int = Field(gt=0, le=262_144)
    expression_type: DependencyExpressionType
    value_ids: tuple[str, ...] = Field(max_length=MAX_TARGET_RECORDS)
    nested_call_offsets: tuple[int, ...] = Field(max_length=MAX_TARGET_RECORDS)
    shortfalls: tuple[str, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def exact_expression(self) -> Self:
        if self.byte_end <= self.byte_start:
            raise ValueError("argument expression is empty or reversed")
        for population in (self.value_ids, self.shortfalls):
            if population != tuple(sorted(set(population))):
                raise ValueError("argument evidence is not sorted and unique")
        if self.nested_call_offsets != tuple(sorted(set(self.nested_call_offsets))):
            raise ValueError("argument call offsets are not sorted and unique")
        if any(not self.byte_start <= i < self.byte_end for i in self.nested_call_offsets):
            raise ValueError("argument call evidence leaves its source span")
        if self.expression_type.shortfall and self.expression_type.shortfall not in self.shortfalls:
            raise ValueError("argument omits its type shortfall")
        return self


class DependencyBaseArgumentCall(_Record):
    source: str = Field(pattern=_PATH, max_length=512)
    call_byte_start: int = Field(ge=0, lt=262_144)
    owner_type_id: str = Field(pattern=_SHA)
    target_id: str = Field(pattern=_SHA)


class DependencyConstructorBinding(_Record):
    """Nominal constructor source dependencies, not initialization order or deployability."""

    target_id: str = Field(pattern=_SHA)
    required_type_ids: tuple[str, ...] = Field(min_length=1, max_length=MAX_TARGET_RECORDS)
    constructor_member_ids: tuple[str, ...] = Field(max_length=MAX_TARGET_RECORDS)
    implicit_type_ids: tuple[str, ...] = Field(max_length=MAX_TARGET_RECORDS)
    base_argument_calls: tuple[DependencyBaseArgumentCall, ...] = Field(
        max_length=MAX_TARGET_RECORDS
    )

    @model_validator(mode="after")
    def exact_population(self) -> Self:
        for values in (self.required_type_ids, self.constructor_member_ids, self.implicit_type_ids):
            if values != tuple(sorted(set(values))):
                raise ValueError("constructor dependency identities must be exact and unique")
        if self.target_id not in self.required_type_ids or not set(self.implicit_type_ids) <= set(
            self.required_type_ids
        ):
            raise ValueError("constructor dependency leaves its nominal ancestry")
        sites = tuple((c.source, c.call_byte_start) for c in self.base_argument_calls)
        if sites != tuple(sorted(set(sites))) or any(
            c.target_id not in self.required_type_ids
            or c.owner_type_id not in self.required_type_ids
            for c in self.base_argument_calls
        ):
            raise ValueError("base argument population leaves its exact nominal ancestry")
        return self


class DependencyTypedCall(_Record):
    source: str = Field(pattern=_PATH, max_length=512)
    source_sha256: str = Field(pattern=_SHA)
    byte_start: int = Field(ge=0, lt=262_144)
    byte_end: int = Field(gt=0, le=262_144)
    call_byte_start: int = Field(ge=0, lt=262_144)
    scope_id: str | None = Field(pattern=_SHA)
    callee: str = Field(min_length=1, max_length=512)
    dispatch: Literal[
        "MEMBER",
        "LIBRARY",
        "INTERNAL",
        "CONVERSION",
        "INTRINSIC",
        "UNRESOLVED",
        "MODIFIER",
        "IMPLICIT_MODIFIER",
        "CREATION",
        "BASE_CONSTRUCTOR",
    ]
    receiver: DependencyArgumentExpression | None
    arguments: tuple[DependencyArgumentExpression, ...] = Field(max_length=64)
    result_types: tuple[DependencyExpressionType, ...] = Field(max_length=64)
    candidate_member_ids: tuple[str, ...] = Field(max_length=MAX_TARGET_RECORDS)
    member_ids: tuple[str, ...] = Field(max_length=MAX_TARGET_RECORDS)
    implementation_ids: tuple[str, ...] = Field(max_length=MAX_TARGET_RECORDS)
    implementation_member_ids: tuple[str, ...] = Field(max_length=MAX_TARGET_RECORDS)
    constructor_binding: DependencyConstructorBinding | None = None
    shortfalls: tuple[str, ...] = Field(max_length=64)
    resolution: Literal["STATIC_DECLARATIONS_BOUND", "NOT_ESTABLISHED"]

    @model_serializer(mode="wrap")
    def preserve_preconstructor_bytes(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        result: dict[str, Any] = handler(self)
        if self.constructor_binding is None:
            result.pop("constructor_binding", None)
        return result

    @model_validator(mode="after")
    def exact_call(self) -> Self:
        implicit = self.dispatch == "IMPLICIT_MODIFIER"
        if not self.byte_start <= self.call_byte_start < self.byte_end or (
            (self.byte_start == self.call_byte_start) != implicit
        ):
            raise ValueError("typed call opening leaves its source span")
        if implicit and (self.arguments or self.receiver or self.result_types):
            raise ValueError("implicit modifier cannot have arguments, a receiver or returns")
        if self.dispatch == "MODIFIER" and (self.receiver or self.result_types):
            raise ValueError("modifier application cannot return a value or have a receiver")
        for population in (
            self.candidate_member_ids,
            self.member_ids,
            self.implementation_ids,
            self.implementation_member_ids,
            self.shortfalls,
        ):
            if population != tuple(sorted(set(population))):
                raise ValueError("typed call evidence is not sorted and unique")
        if not set(self.member_ids) <= set(self.candidate_member_ids):
            raise ValueError("typed call selection leaves its candidates")
        expressions = (*self.arguments, *((self.receiver,) if self.receiver else ()))
        if any(
            not self.byte_start <= a.byte_start < a.byte_end <= self.byte_end for a in expressions
        ):
            raise ValueError("typed call expression leaves its source span")
        construction = self.constructor_binding
        if construction is not None and (
            self.dispatch not in {"CREATION", "BASE_CONSTRUCTOR"}
            or self.receiver is not None
            or self.implementation_ids != construction.required_type_ids
            or self.implementation_member_ids != construction.constructor_member_ids
            or (self.dispatch == "BASE_CONSTRUCTOR" and self.result_types)
            or (
                self.dispatch == "CREATION"
                and (
                    len(self.result_types) != 1
                    or self.result_types[0].target_id != construction.target_id
                )
            )
        ):
            raise ValueError("constructor binding differs from its exact dispatch")
        bound = not self.shortfalls and (
            (
                construction is not None
                and (
                    len(self.member_ids) == 1
                    or (
                        not self.member_ids
                        and construction.target_id in construction.implicit_type_ids
                    )
                )
            )
            if self.dispatch in {"CREATION", "BASE_CONSTRUCTOR"}
            else self.dispatch in {"CONVERSION", "INTRINSIC"} or len(self.member_ids) == 1
        )
        if (self.resolution == "STATIC_DECLARATIONS_BOUND") != bound:
            raise ValueError("typed call claim differs from its exact shortfalls")
        return self


class DependencyTypedMembers(_Record):
    primary: str = Field(pattern=_PATH, max_length=512)
    members: tuple[str, ...] = Field(min_length=1, max_length=256)
    unresolved_call_indices: tuple[int, ...] = Field(max_length=MAX_TARGET_RECORDS)
    gap_indices: tuple[int, ...] = Field(max_length=MAX_TARGET_RECORDS)


class DependencyCallContext(_Record):
    policy: Literal[
        "SOURCE_ARGUMENT_RETURN_CALL_RESOLUTION_V1",
        "SOURCE_CALL_AND_MODIFIER_RESOLUTION_V2",
        "SOURCE_CALL_MODIFIER_AND_CONSTRUCTOR_RESOLUTION_V3",
    ] = "SOURCE_ARGUMENT_RETURN_CALL_RESOLUTION_V1"
    scope: Literal["LEXICAL_CALL_CANDIDATES_NOT_COMPLETE_SOLIDITY_OR_DEPLOYED_DISPATCH"] = (
        "LEXICAL_CALL_CANDIDATES_NOT_COMPLETE_SOLIDITY_OR_DEPLOYED_DISPATCH"
    )
    source_inventory_sha256: str = Field(pattern=_SHA)
    scoped_context_sha256: str = Field(pattern=_SHA)
    calls: tuple[DependencyTypedCall, ...] = Field(max_length=MAX_TARGET_RECORDS)
    gaps: tuple[DependencyTargetGap, ...] = Field(max_length=MAX_TARGET_RECORDS)
    primaries: tuple[DependencyTypedMembers, ...] = Field(min_length=1, max_length=256)
    complete_static_resolution: Literal[False] = False

    @field_validator("complete_static_resolution", mode="before")
    @classmethod
    def no_complete_typecheck(cls, value: object) -> Literal[False]:
        if value is not False:
            raise ValueError("argument and return bindings are not complete Solidity resolution")
        return False

    @model_validator(mode="after")
    def exact_population(self) -> Self:
        paths = tuple(p.primary for p in self.primaries)
        identities = tuple((c.source, c.call_byte_start) for c in self.calls)
        if paths != tuple(sorted(set(paths))) or identities != tuple(sorted(set(identities))):
            raise ValueError("typed call/source population must be sorted and unique")
        lookup = {(c.source, c.call_byte_start): c for c in self.calls}
        for call in self.calls:
            if self.policy != "SOURCE_CALL_MODIFIER_AND_CONSTRUCTOR_RESOLUTION_V3" and (
                call.constructor_binding is not None
                or call.dispatch in {"CREATION", "BASE_CONSTRUCTOR"}
            ):
                raise ValueError("constructor bindings require their versioned resolution policy")
            if self.policy == "SOURCE_ARGUMENT_RETURN_CALL_RESOLUTION_V1" and call.dispatch in {
                "MODIFIER",
                "IMPLICIT_MODIFIER",
            }:
                raise ValueError("modifier bindings require their versioned resolution policy")
            if call.source not in paths:
                raise ValueError("typed call leaves its source universe")
            if call.constructor_binding is not None:
                for site in call.constructor_binding.base_argument_calls:
                    child = lookup.get((site.source, site.call_byte_start))
                    if (
                        child is None
                        or child.dispatch != "BASE_CONSTRUCTOR"
                        or (
                            child.constructor_binding is None
                            or child.constructor_binding.target_id != site.target_id
                        )
                    ):
                        raise ValueError(
                            "constructor argument reference lacks its exact typed call"
                        )
            for expression in (*call.arguments, *((call.receiver,) if call.receiver else ())):
                for offset in expression.nested_call_offsets:
                    child = lookup.get((call.source, offset))
                    if child is None or not (
                        expression.byte_start <= child.byte_start
                        and child.byte_end <= expression.byte_end
                        and child.call_byte_start < call.byte_end
                        and child.call_byte_start != call.call_byte_start
                    ):
                        raise ValueError(
                            "typed expression references a missing or noncontained call"
                        )
        for primary in self.primaries:
            if (
                primary.members != tuple(sorted(set(primary.members)))
                or primary.primary not in primary.members
                or not set(primary.members) <= set(paths)
                or primary.unresolved_call_indices
                != tuple(
                    i
                    for i, c in enumerate(self.calls)
                    if c.source in primary.members and c.resolution == "NOT_ESTABLISHED"
                )
                or primary.gap_indices
                != tuple(i for i, g in enumerate(self.gaps) if g.source in primary.members)
            ):
                raise ValueError("typed primary membership or shortfalls differ")
        if any(g.source not in paths for g in self.gaps):
            raise ValueError("typed parse gap leaves its source universe")
        if len(self.model_dump_json().encode()) > MAX_TARGET_CONTEXT_BYTES:
            raise ValueError("complete typed call context exceeds its byte ceiling")
        return self


def _unknown(reason: str) -> DependencyExpressionType:
    return DependencyExpressionType(kind="UNKNOWN", spelling="UNKNOWN", shortfall=reason)


def _builtin(name: str) -> DependencyExpressionType:
    return DependencyExpressionType(
        kind="BUILTIN", spelling={"uint": "uint256", "int": "int256"}.get(name, name)
    )


@dataclass(frozen=True)
class _Value:
    type: DependencyExpressionType
    values: tuple[str, ...] = ()
    calls: tuple[int, ...] = ()
    gaps: tuple[str, ...] = ()


class _Resolver:
    def __init__(self, builder: _Builder, sources: tuple[tuple[str, bytes], ...]) -> None:
        self.builder = builder
        self.sources = dict(sources)
        self.sites: dict[tuple[str, int], int] = {}
        self.results: dict[tuple[str, int], DependencyTypedCall] = {}

    def bounded(self, depth: int) -> None:
        self.builder.charge()
        if depth > MAX_EXPRESSION_DEPTH:
            raise ValueError("complete argument/call resolution exceeds its depth ceiling")

    def type(self, binding: DependencyTypeBinding) -> DependencyExpressionType:
        if binding.target_id is not None:
            if self.builder.types[binding.target_id].kind == "library":
                return _unknown("LIBRARY_VALUE_TYPE_UNSUPPORTED")
            return DependencyExpressionType(
                kind="NOMINAL", spelling=binding.spelling, target_id=binding.target_id
            )
        if binding.shortfall == "NON_CONTRACT_VALUE_TYPE" and _BUILTIN.fullmatch(binding.spelling):
            if binding.spelling in {"bytes", "string"}:
                return _unknown("REFERENCE_LOCATION_NOT_ESTABLISHED")
            return _builtin(binding.spelling)
        return _unknown(binding.shortfall or "DECLARED_TYPE_NOT_ESTABLISHED")

    def accepts(
        self, value: DependencyExpressionType, target: DependencyExpressionType
    ) -> bool | None:
        self.builder.charge()
        if value.kind == "UNKNOWN" or target.kind == "UNKNOWN":
            return None
        if value.kind == target.kind == "NOMINAL":
            assert value.target_id is not None and target.target_id is not None
            return (
                target.target_id == value.target_id
                or target.target_id in self.builder.ancestors[value.target_id]
            )
        if value.kind == "INTEGER_LITERAL":
            if target.kind != "BUILTIN" or not re.fullmatch(r"u?int[0-9]+", target.spelling):
                return False
            assert value.integer_value is not None
            bits = int(target.spelling.lstrip("uint"))
            n = int(value.integer_value)
            return bool(
                0 <= n < 2**bits
                if target.spelling.startswith("uint")
                else -(2 ** (bits - 1)) <= n < 2 ** (bits - 1)
            )
        if value.kind == "STRING_LITERAL":
            # Fixed-size byte literals require escape/UTF-8 length analysis not supplied here.
            if target.kind != "BUILTIN":
                return False
            return (
                True
                if target.spelling in {"bytes", "string"}
                else None
                if target.spelling.startswith("bytes")
                else False
            )
        if value.kind == target.kind == "BUILTIN":
            if value.spelling == target.spelling or (value.spelling, target.spelling) == (
                "addresspayable",
                "address",
            ):
                return True
            fixed_bytes = [re.fullmatch(r"bytes([0-9]+)", t.spelling) for t in (value, target)]
            if all(fixed_bytes):
                left, right = fixed_bytes
                assert left is not None and right is not None
                return int(left[1]) <= int(right[1])
            integers = [re.fullmatch(r"(u?int)([0-9]+)", t.spelling) for t in (value, target)]
            if all(integers):
                a, b = integers
                assert a is not None and b is not None
                return (a[1] == b[1] and int(a[2]) <= int(b[2])) or (
                    a[1] == "uint" and b[1] == "int" and int(a[2]) < int(b[2])
                )
        return False

    def postfix_start(self, source: str, end: int, depth: int = 0) -> int | None:
        self.bounded(depth)
        if end < 0:
            return None
        unit = self.builder.units[source]
        tokens = unit.tokens
        token = tokens[end]
        if token.kind == "identifier":
            if token.value in _NON_CALLS:
                return None
            if end >= 2 and tokens[end - 1].value == ".":
                return self.postfix_start(source, end - 2, depth + 1)
            return end
        if token.value in {")", "]", "}"} and end in unit.pairs:
            opening = unit.pairs[end]
            before = self.postfix_start(source, opening - 1, depth + 1)
            return before if before is not None else opening if token.value == ")" else None
        return None

    def census(self) -> None:
        for source, unit in self.builder.units.items():
            for opening, token in enumerate(unit.tokens):
                self.builder.charge()
                if (
                    token.kind != "punctuation"
                    or token.value != "("
                    or opening in self.builder.excluded[source]
                ):
                    continue
                first = self.postfix_start(source, opening - 1)
                if first is not None:
                    self.sites[source, opening] = first
                    if len(self.sites) > MAX_TARGET_RECORDS:
                        raise ValueError("complete lexical call census exceeds its record ceiling")
        for key, (first, _name_end, _last) in self.builder.modifiers.items():
            self.builder.charge()
            self.sites[key] = first
            if len(self.sites) > MAX_TARGET_RECORDS:
                raise ValueError("complete modifier/call census exceeds its record ceiling")

    def combine(
        self, type_: DependencyExpressionType, *values: _Value, gaps: tuple[str, ...] = ()
    ) -> _Value:
        self.builder.charge(sum(len(v.values) + len(v.calls) + len(v.gaps) for v in values))
        return _Value(
            type_,
            tuple(sorted({i for v in values for i in v.values})),
            tuple(sorted({i for v in values for i in v.calls})),
            tuple(
                sorted(
                    {
                        *gaps,
                        *(g for v in values for g in v.gaps),
                        *((type_.shortfall,) if type_.shortfall else ()),
                    }
                )
            ),
        )

    def expression(self, source: str, begin: int, end: int, depth: int = 0) -> _Value:
        self.bounded(depth)
        unit = self.builder.units[source]
        tokens = unit.tokens
        if begin >= end:
            return _Value(_unknown("EMPTY_ARGUMENT_EXPRESSION"))
        raw = self.sources[source][tokens[begin].start : tokens[end - 1].end]
        if re.fullmatch(rb"-?(?:0|[1-9][0-9]{0,77}|0x[0-9a-fA-F]{1,64})", raw):
            digits = raw.removeprefix(b"-")
            if digits.startswith(b"0x") and len(digits) == 42:
                return _Value(_unknown("HEX_ADDRESS_LITERAL_TYPE_UNRESOLVED"))
            value = int(digits, 16 if digits.startswith(b"0x") else 10) * (
                -1 if raw.startswith(b"-") else 1
            )
            if -(2**255) <= value < 2**256:
                return _Value(
                    DependencyExpressionType(
                        kind="INTEGER_LITERAL", spelling="integer_literal", integer_value=str(value)
                    )
                )
            return _Value(_unknown("INTEGER_LITERAL_OUTSIDE_SUPPORTED_DOMAIN"))
        if tokens[begin].value == "(" and unit.pairs.get(begin) == end - 1:
            return self.expression(source, begin + 1, end - 1, depth + 1)
        # Only top-level operators split the expression. Delimited argument/receiver expressions
        # are recursively resolved, never flattened into text or stripped of nested calls.
        operators: list[tuple[int, int, str]] = []
        cursor = begin
        while cursor < end:
            self.builder.charge()
            token = tokens[cursor]
            if token.value in {"(", "[", "{"} and cursor in unit.pairs:
                cursor = unit.pairs[cursor] + 1
                continue
            op = token.value
            width = 1
            if (
                cursor + 1 < end
                and token.end == tokens[cursor + 1].start
                and op + tokens[cursor + 1].value in _PRECEDENCE
            ):
                op += tokens[cursor + 1].value
                width = 2
            if (
                op in _PRECEDENCE
                and cursor > begin
                and tokens[cursor - 1].value not in {*_PRECEDENCE, "!", "~", "?", ":"}
            ):
                operators.append((cursor, width, op))
            cursor += width
        if operators:
            position, width, operator = min(
                operators,
                key=lambda item: (_PRECEDENCE[item[2]], item[0] if item[2] == "**" else -item[0]),
            )
            left = self.expression(source, begin, position, depth + 1)
            right = self.expression(source, position + width, end, depth + 1)
            result = _unknown("BINARY_EXPRESSION_TYPE_UNRESOLVED")
            if operator in {"&&", "||"} and left.type == right.type == _builtin("bool"):
                result = _builtin("bool")
            elif operator in {"==", "!=", "<", ">", "<=", ">="} and (
                self.accepts(left.type, right.type) is True
                or self.accepts(right.type, left.type) is True
            ):
                if operator in {"==", "!="} or all(
                    re.fullmatch(r"u?int[0-9]+", t.spelling)
                    for t in (left.type, right.type)
                    if t.kind != "INTEGER_LITERAL"
                ):
                    result = _builtin("bool")
            elif operator not in {"<<", ">>", "**"}:
                for target, other in ((left.type, right.type), (right.type, left.type)):
                    if (
                        target.kind == "BUILTIN"
                        and re.fullmatch(r"u?int[0-9]+", target.spelling)
                        and self.accepts(other, target) is True
                    ):
                        result = target
                        break
            return self.combine(result, left, right)
        if tokens[begin].value in {"!", "~", "-", "+"}:
            operand = self.expression(source, begin + 1, end, depth + 1)
            result = (
                operand.type
                if (tokens[begin].value == "!" and operand.type == _builtin("bool"))
                or (
                    tokens[begin].value in {"~", "-"}
                    and operand.type.kind == "BUILTIN"
                    and re.fullmatch(
                        r"int[0-9]+" if tokens[begin].value == "-" else r"u?int[0-9]+",
                        operand.type.spelling,
                    )
                )
                else _unknown("UNARY_EXPRESSION_TYPE_UNRESOLVED")
            )
            return self.combine(result, operand)
        if tokens[end - 1].value == ")":
            opening = unit.pairs.get(end - 1)
            if opening is not None and self.sites.get((source, opening)) == begin:
                call = self.call(source, opening, depth + 1)
                result = (
                    call.result_types[0]
                    if len(call.result_types) == 1 and not call.shortfalls
                    else _unknown("DEPENDENT_CALL_RESULT_NOT_ESTABLISHED")
                )
                expressions = (*call.arguments, *((call.receiver,) if call.receiver else ()))
                return _Value(
                    result,
                    tuple(sorted({v for a in expressions for v in a.value_ids})),
                    tuple(
                        sorted(
                            {
                                call.call_byte_start,
                                *(i for a in expressions for i in a.nested_call_offsets),
                            }
                        )
                    ),
                    tuple(
                        sorted(
                            {*call.shortfalls, *((result.shortfall,) if result.shortfall else ())}
                        )
                    ),
                )
        scope = self.builder.at_scope(source, tokens[begin].start)
        if end == begin + 1:
            token = tokens[begin]
            if token.kind == "identifier" and token.value in {"true", "false"}:
                return _Value(_builtin("bool"))
            if token.kind == "string":
                if "\\" in token.value or not token.value.isascii():
                    return _Value(_unknown("STRING_LITERAL_ENCODING_UNRESOLVED"))
                return _Value(
                    DependencyExpressionType(kind="STRING_LITERAL", spelling="string_literal")
                )
            if token.value == "this" and scope is not None:
                declaration = self.builder.types[scope.owner_type_id]
                return _Value(
                    DependencyExpressionType(
                        kind="NOMINAL", spelling=declaration.name, target_id=declaration.id
                    )
                )
            values = self.builder.lookup(scope, token.start, token.value)
            if len(values) == 1:
                return _Value(self.type(values[0].value_type), (values[0].id,))
            return _Value(
                _unknown(
                    "AMBIGUOUS_VALUE_DECLARATION" if values else "EXPRESSION_NAME_NOT_RESOLVED"
                ),
                tuple(sorted(v.id for v in values)),
            )
        spelling = _qualified(tokens[begin:end])
        if spelling in {
            "msg.sender",
            "tx.origin",
            "msg.value",
            "block.number",
            "block.timestamp",
            "block.chainid",
        } and not self.builder.shadowed(scope, tokens[begin].start, spelling.split(".")[0]):
            self.builder.charge(len(tokens))
            versions = [
                "".join(
                    t.value
                    for t in tokens[
                        i + 2 : next(
                            (j for j in range(i + 2, len(tokens)) if tokens[j].value == ";"),
                            len(tokens),
                        )
                    ]
                )
                for i, token in enumerate(tokens[:-1])
                if token.value == "pragma" and tokens[i + 1].value == "solidity"
            ]
            if not versions or any(re.fullmatch(r"\^?0\.8\.[0-9]+", v) is None for v in versions):
                return _Value(_unknown("GLOBAL_VALUE_LANGUAGE_VERSION_NOT_ESTABLISHED"))
            return _Value(
                _builtin("address" if spelling in {"msg.sender", "tx.origin"} else "uint256")
            )
        return _Value(_unknown("EXPRESSION_FORM_NOT_RESOLVED"))

    def argument(
        self, source: str, begin: int, end: int, depth: int
    ) -> DependencyArgumentExpression:
        value = self.expression(source, begin, end, depth)
        tokens = self.builder.units[source].tokens
        return DependencyArgumentExpression(
            byte_start=tokens[begin].start,
            byte_end=tokens[end - 1].end,
            expression_type=value.type,
            value_ids=value.values,
            nested_call_offsets=value.calls,
            shortfalls=tuple(
                sorted({*value.gaps, *((value.type.shortfall,) if value.type.shortfall else ())})
            ),
        )

    def conversion(self, value: DependencyExpressionType, target: DependencyExpressionType) -> bool:
        if self.accepts(value, target) is True:
            return True
        if target.kind == "NOMINAL":
            if value.kind == "BUILTIN" and value.spelling in {"address", "addresspayable"}:
                assert target.target_id is not None
                # Contract payability requires semantic header analysis outside this slice.
                if value.spelling == "addresspayable":
                    return True
                self.builder.charge(len(self.builder.functions))
                owners = {target.target_id} | self.builder.ancestors[target.target_id]
                return not any(
                    f.owner_type_id in owners and f.kind in {"receive", "fallback"}
                    for f in self.builder.functions
                )
            if value.kind == "NOMINAL":
                assert target.target_id is not None and value.target_id is not None
                self.builder.charge(len(self.builder.functions))
                owners = {target.target_id} | self.builder.ancestors[target.target_id]
                return value.target_id in self.builder.ancestors[target.target_id] and not any(
                    f.owner_type_id in owners and f.kind in {"receive", "fallback"}
                    for f in self.builder.functions
                )
        if value.kind == target.kind == "BUILTIN":
            a, b = (re.fullmatch(r"(u?int)([0-9]+)", t.spelling) for t in (value, target))
            if a and b:
                return a[1] == b[1] or a[2] == b[2]
            if target.spelling == "address":
                return value.spelling in {"uint160", "bytes20", "addresspayable"}
        if target.spelling == "address" and value.kind == "INTEGER_LITERAL":
            assert value.integer_value is not None
            return 0 <= int(value.integer_value) < 2**160
        return target.spelling == "address" and value.kind == "NOMINAL"

    def call(self, source: str, opening: int, depth: int = 0) -> DependencyTypedCall:
        self.bounded(depth)
        key = (source, opening)
        if key in self.results:
            return self.results[key]
        builder = self.builder
        unit = builder.units[source]
        tokens = unit.tokens
        first = self.sites[key]
        header = builder.modifiers.get(key)
        implicit = header is not None and first == opening
        closing = header[2] if header is not None else unit.pairs.get(opening, opening)
        scope = builder.at_scope(source, tokens[opening].start)
        shortfalls: set[str] = set()
        if scope is None or builder.unsafe(scope):
            shortfalls.add("LEXICAL_SCOPE_NOT_ESTABLISHED")
        callee_end = header[1] if header is not None else opening
        if header is None and tokens[opening - 1].value == "}" and opening - 1 in unit.pairs:
            callee_end = unit.pairs[opening - 1]
            shortfalls.add("CALL_OPTIONS_NOT_RESOLVED")
        if closing == opening and not implicit:
            shortfalls.add("CALL_ARGUMENTS_NOT_PARSED")
        ranges = [] if implicit else builder.segments(source, opening + 1, closing, ",")
        if len(ranges) > 64:
            raise ValueError("complete typed argument population exceeds its ceiling")
        arguments = []
        for begin, end in ranges:
            if begin == end:
                shortfalls.add("EMPTY_ARGUMENT_EXPRESSION")
            else:
                arguments.append(self.argument(source, begin, end, depth + 1))
        for arg in arguments:
            shortfalls.update(arg.shortfalls)
        receiver = None
        dispatch = "UNRESOLVED"
        result_types: tuple[DependencyExpressionType, ...] = ()
        candidates: tuple[DependencyFunctionDeclaration, ...] = ()
        members: tuple[DependencyFunctionDeclaration, ...] = ()
        implementations: set[str] = set()
        bodies: set[str] = set()
        owner: str | None = None
        spelling = _qualified(tokens[first:callee_end])
        label = spelling or tokens[callee_end - 1].value
        if len(label) > 512:
            raise ValueError("complete call spelling exceeds its ceiling")
        type_binding = builder.binding(source, tokens[first].start, spelling or "UNRESOLVED")
        target_type = self.type(type_binding)
        shadowed = spelling is not None and builder.shadowed(
            scope, tokens[opening].start, spelling.split(".")[0]
        )
        qualified_modifier = False
        if header is not None:
            dispatch = "IMPLICIT_MODIFIER" if implicit else "MODIFIER"
            if scope is None or spelling is None:
                shortfalls.add("MODIFIER_OWNER_NOT_ESTABLISHED")
            elif type_binding.target_id is not None:
                # Constructor base invocations are not conversions or modifier invocations.
                shortfalls.add("BASE_CONSTRUCTOR_HEADER_UNRESOLVED")
            elif "." in spelling:
                modifier_prefix, label = spelling.rsplit(".", 1)
                base = builder.binding(source, tokens[first].start, modifier_prefix)
                if base.target_id not in builder.ancestors[scope.owner_type_id] or builder.lookup(
                    scope, tokens[first].start, modifier_prefix.split(".")[0]
                ):
                    shortfalls.add("QUALIFIED_MODIFIER_BASE_NOT_ESTABLISHED")
                else:
                    owner = base.target_id
                    qualified_modifier = True
            else:
                owner = scope.owner_type_id
                if builder.lookup(scope, tokens[first].start, spelling):
                    shortfalls.add("MODIFIER_NAME_SHADOWED")
        elif (
            first
            and tokens[first - 1].value in {"new", "emit", "revert"}
            and not (builder.include_constructors and tokens[first - 1].value == "new")
        ):
            shortfalls.add("CREATION_OR_EVENT_ERROR_CALL_UNRESOLVED")
        elif spelling and not shadowed and target_type.kind in {"BUILTIN", "NOMINAL"}:
            dispatch = "CONVERSION"
            result_types = (target_type,)
            if target_type.kind == "NOMINAL" and builder.gaps:
                shortfalls.add("CONVERSION_NAMESPACE_OR_PARSE_GAPS")
            if len(arguments) != 1 or not self.conversion(
                arguments[0].expression_type, target_type
            ):
                shortfalls.add("EXPLICIT_CONVERSION_NOT_ESTABLISHED")
            if target_type.target_id and builder.types[target_type.target_id].kind == "library":
                shortfalls.add("LIBRARY_VALUE_CONVERSION_UNSUPPORTED")
        elif (
            callee_end == first + 1
            and spelling
            and not builder.lookup(scope, tokens[opening].start, spelling)
        ):
            if spelling in {"require", "assert", "revert"} and not shadowed:
                dispatch = "INTRINSIC"
                valid = (
                    spelling == "revert"
                    and len(arguments) <= 1
                    and (
                        not arguments
                        or self.accepts(arguments[0].expression_type, _builtin("string")) is True
                    )
                ) or (
                    spelling in {"require", "assert"}
                    and len(arguments) in ({1, 2} if spelling == "require" else {1})
                    and arguments[0].expression_type == _builtin("bool")
                    and (
                        len(arguments) == 1
                        or self.accepts(arguments[1].expression_type, _builtin("string")) is True
                    )
                )
                if not valid:
                    shortfalls.add("INTRINSIC_ARGUMENT_TYPES_NOT_ESTABLISHED")
            elif scope is not None:
                dispatch, owner = "INTERNAL", scope.owner_type_id
        elif callee_end >= first + 3 and tokens[callee_end - 2].value == ".":
            member = tokens[callee_end - 1].value
            prefix = _qualified(tokens[first : callee_end - 2])
            prefix_binding = builder.binding(source, tokens[first].start, prefix or "UNRESOLVED")
            if (
                prefix
                and prefix_binding.target_id
                and not builder.shadowed(scope, tokens[opening].start, prefix.split(".")[0])
            ):
                owner = prefix_binding.target_id
                dispatch = "LIBRARY"
                if builder.types[owner].kind != "library":
                    shortfalls.add("EXPLICIT_BASE_MEMBER_DISPATCH_UNRESOLVED")
            else:
                receiver = self.argument(source, first, callee_end - 2, depth + 1)
                shortfalls.update(receiver.shortfalls)
                owner = receiver.expression_type.target_id
                dispatch = "MEMBER"
                if owner is None:
                    shortfalls.add("CALL_RECEIVER_TYPE_NOT_ESTABLISHED")
            label = member
        else:
            shortfalls.add("CALLABLE_EXPRESSION_NOT_RESOLVED")
        if owner is not None:
            member_kind: Literal["function", "modifier"] = (
                "modifier" if header is not None else "function"
            )
            candidates = builder.members(owner, label, len(arguments), member_kind)
            matches: list[DependencyFunctionDeclaration] = []
            uncertain = False
            for function in candidates:
                conversions = [
                    self.accepts(a.expression_type, self.type(p))
                    for a, p in zip(arguments, function.parameters, strict=True)
                ]
                if False not in conversions:
                    matches.append(function)
                    uncertain = uncertain or None in conversions
            members = tuple(matches)
            if not candidates:
                shortfalls.add("MEMBER_DECLARATION_NOT_RESOLVED")
            if not members:
                shortfalls.add("NO_APPLICABLE_OVERLOAD")
            elif len(members) != 1:
                shortfalls.add("OVERLOAD_OR_INHERITED_MEMBER_AMBIGUITY")
            if uncertain:
                shortfalls.add("ARGUMENT_CONVERSION_NOT_ESTABLISHED")
            if len(members) == 1 and not uncertain:
                result_types = tuple(self.type(p) for p in members[0].returns)
                if any(t.kind == "UNKNOWN" for t in result_types):
                    shortfalls.add("RETURN_TYPE_NOT_ESTABLISHED")
            for function in members:
                if header is not None and (
                    function.returns or function.visibility != "UNSPECIFIED"
                ):
                    shortfalls.add("MODIFIER_DECLARATION_FORM_NOT_ESTABLISHED")
                if dispatch == "MEMBER" and function.visibility not in {"public", "external"}:
                    shortfalls.add("MEMBER_EXTERNAL_VISIBILITY_NOT_ESTABLISHED")
                if dispatch == "INTERNAL" and (
                    function.visibility not in {"private", "internal", "public"}
                    or (function.visibility == "private" and function.owner_type_id != owner)
                ):
                    shortfalls.add("INTERNAL_MEMBER_VISIBILITY_NOT_ESTABLISHED")
                if dispatch == "LIBRARY" and function.visibility not in {
                    "internal",
                    "public",
                    "external",
                }:
                    shortfalls.add("LIBRARY_MEMBER_VISIBILITY_NOT_ESTABLISHED")
            builder.charge(len(builder.types))
            implementations.update(
                d.id
                for d in builder.types.values()
                if d.kind != "interface"
                and (d.id == owner or (not qualified_modifier and owner in builder.ancestors[d.id]))
            )
            if not implementations:
                shortfalls.add("NO_SUPPLIED_IMPLEMENTER")
            for implementation in implementations:
                if header is not None:
                    # A changed signature must not make a declared override disappear behind
                    # a matching inherited body. Inspect all named declarations, before arity.
                    for modifier in builder.members(implementation, label, None, "modifier"):
                        shortfalls.update(self.modifier_shortfalls(modifier))
                supplied = builder.members(implementation, label, len(arguments), member_kind)
                matched = [
                    f
                    for f in supplied
                    if f.body_byte_start is not None
                    and any(builder.signature(f) == builder.signature(m) for m in members)
                ]
                bodies.update(f.id for f in matched)
                if len(matched) != 1:
                    shortfalls.add("IMPLEMENTATION_MEMBER_BODY_NOT_UNIQUE")
                for body in matched:
                    if header is not None:
                        shortfalls.update(self.modifier_shortfalls(body))
                    if not any(
                        builder.type_signature(body.returns) == builder.type_signature(m.returns)
                        for m in members
                    ) or (dispatch == "MEMBER" and body.visibility not in {"public", "external"}):
                        shortfalls.add("IMPLEMENTATION_SIGNATURE_OR_VISIBILITY_MISMATCH")
                    if (
                        dispatch == "INTERNAL"
                        and body.visibility not in {"private", "internal", "public"}
                    ) or (
                        dispatch == "LIBRARY"
                        and body.visibility not in {"internal", "public", "external"}
                    ):
                        shortfalls.add("IMPLEMENTATION_SIGNATURE_OR_VISIBILITY_MISMATCH")
            if builder.gaps:
                shortfalls.add("IMPLEMENTATION_NAMESPACE_OR_PARSE_GAPS")
        if dispatch == "UNRESOLVED":
            shortfalls.add("CALL_TARGET_NOT_ESTABLISHED")
        bound = not shortfalls and (dispatch in {"INTRINSIC", "CONVERSION"} or len(members) == 1)
        call = DependencyTypedCall.model_validate(
            dict(
                source=source,
                source_sha256=hashlib.sha256(self.sources[source]).hexdigest(),
                byte_start=tokens[first].start,
                byte_end=tokens[closing].end,
                call_byte_start=tokens[opening].start,
                scope_id=scope.id if scope else None,
                callee=label,
                dispatch=dispatch,
                receiver=receiver,
                arguments=tuple(arguments),
                result_types=result_types,
                candidate_member_ids=tuple(sorted(f.id for f in candidates)),
                member_ids=tuple(sorted(f.id for f in members)),
                implementation_ids=tuple(sorted(implementations)),
                implementation_member_ids=tuple(sorted(bodies)),
                shortfalls=tuple(sorted(shortfalls)),
                resolution="STATIC_DECLARATIONS_BOUND" if bound else "NOT_ESTABLISHED",
            )
        )
        self.results[key] = call
        return call

    def modifier_shortfalls(self, function: DependencyFunctionDeclaration) -> set[str]:
        """Keep illegal/ambiguous nominal modifier declarations from earning body bindings."""
        builder = self.builder
        builder.charge(len(builder.functions))
        same_name = [
            f for f in builder.functions if f.kind == "modifier" and f.name == function.name
        ]
        gaps: set[str] = set()
        if function.returns or function.visibility != "UNSPECIFIED":
            gaps.add("MODIFIER_DECLARATION_FORM_NOT_ESTABLISHED")
        if sum(f.owner_type_id == function.owner_type_id for f in same_name) != 1:
            gaps.add("MODIFIER_DECLARATION_NOT_UNIQUE")

        def flags(declaration: DependencyFunctionDeclaration) -> set[str]:
            tokens = builder.units[declaration.source].tokens
            builder.charge(len(tokens))
            end = declaration.body_byte_start or declaration.byte_end
            return {
                t.value
                for t in tokens
                if declaration.byte_start <= t.start < end and t.kind == "identifier"
            }

        ancestors = [
            f for f in same_name if f.owner_type_id in builder.ancestors[function.owner_type_id]
        ]
        if ancestors and "override" not in flags(function):
            gaps.add("MODIFIER_OVERRIDE_NOT_ESTABLISHED")
        for base in ancestors:
            if builder.signature(base) != builder.signature(function) or "virtual" not in flags(
                base
            ):
                gaps.add("MODIFIER_OVERRIDE_NOT_ESTABLISHED")
        return gaps


def build_dependency_call_context(
    *,
    source_files: tuple[tuple[str, bytes], ...],
    imports: tuple[DependencyImport, ...],
    target_context: DependencyTargetContext,
    scoped_context: DependencyScopedContext,
) -> DependencyCallContext:
    """Compute from validated source and exact scopes; all runtime consumers must recompute."""

    if (
        type(target_context) is not DependencyTargetContext
        or type(scoped_context) is not DependencyScopedContext
        or scoped_context.target_context_sha256
        != canonical_sha256(target_context.model_dump(mode="json"))
        or tuple(p for p, _ in source_files) != tuple(p.primary for p in scoped_context.primaries)
    ):
        raise ValueError("typed calls require the exact validated source/target/scope universe")
    include_modifiers = scoped_context.policy != "MODERN_LEXICAL_VALUES_AND_NOMINAL_MEMBERS_V1"
    include_constructors = (
        scoped_context.policy == "MODERN_LEXICAL_VALUES_AND_CONSTRUCTOR_HEADERS_V3"
    )
    builder = _Builder(
        source_files,
        imports,
        target_context,
        include_modifiers=include_modifiers,
        include_constructors=include_constructors,
    )
    builder.parse()
    builder.resolve_declared_types()
    if (tuple(builder.scopes), tuple(builder.values), tuple(builder.functions)) != (
        scoped_context.scopes,
        scoped_context.values,
        scoped_context.functions,
    ):
        raise ValueError("typed call scopes differ from recomputed source declarations")
    resolver: _Resolver
    if include_constructors:
        from mmaudit.solidity.dependency_constructors import _ConstructorResolver

        resolver = _ConstructorResolver(builder, source_files)
    else:
        resolver = _Resolver(builder, source_files)
    resolver.census()
    for source, opening in resolver.sites:
        resolver.call(source, opening)
    calls = tuple(sorted(resolver.results.values(), key=lambda c: (c.source, c.call_byte_start)))
    gaps = tuple(sorted(set(builder.gaps), key=lambda g: (g.source, g.byte_start, g.reason)))
    functions = {f.id: f for f in builder.functions}
    adjacency = {p.primary: set(p.members) for p in scoped_context.primaries}
    for call in calls:
        adjacency[call.source].update(builder.types[i].source for i in call.implementation_ids)
        adjacency[call.source].update(
            functions[i].source for i in (*call.member_ids, *call.implementation_member_ids)
        )
        for type_ in (
            *call.result_types,
            *(a.expression_type for a in call.arguments),
            *((call.receiver.expression_type,) if call.receiver else ()),
        ):
            if type_.target_id:
                adjacency[call.source].add(builder.types[type_.target_id].source)
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
            DependencyTypedMembers(
                primary=primary,
                members=tuple(sorted(members)),
                unresolved_call_indices=tuple(
                    i
                    for i, c in enumerate(calls)
                    if c.source in members and c.resolution == "NOT_ESTABLISHED"
                ),
                gap_indices=tuple(i for i, g in enumerate(gaps) if g.source in members),
            )
        )
    return DependencyCallContext(
        policy="SOURCE_CALL_MODIFIER_AND_CONSTRUCTOR_RESOLUTION_V3"
        if include_constructors
        else "SOURCE_CALL_AND_MODIFIER_RESOLUTION_V2"
        if include_modifiers
        else "SOURCE_ARGUMENT_RETURN_CALL_RESOLUTION_V1",
        source_inventory_sha256=target_context.source_inventory_sha256,
        scoped_context_sha256=canonical_sha256(scoped_context.model_dump(mode="json")),
        calls=calls,
        gaps=gaps,
        primaries=tuple(primaries),
    )
