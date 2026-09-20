"""Bounded, independent Solidity-subset grammar and exact typed-call census comparison.

Every source is parsed to EOF or retains its unparsed suffix, including a precise failure
offset. Supported grammar accounting is not type correctness, compilation or call closure.
Unsupported language forms never become a successful empty call census.
"""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING, Literal, Self

from pydantic import Field, field_validator, model_validator

from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.solidity.dependency_calls import DependencyCallContext
from mmaudit.solidity.dependency_targets import (
    MAX_TARGET_CONTEXT_BYTES,
    MAX_TARGET_RECORDS,
    _Record,
)

if TYPE_CHECKING:
    from mmaudit.solidity.dependency_closure import _Token

MAX_SYNTAX_DEPTH = 32
MAX_SYNTAX_WORK = 1_000_000
_SHA = r"^[0-9a-f]{64}$"
_PATH = r"^(?:[A-Za-z0-9][A-Za-z0-9._-]*/)*[A-Za-z0-9][A-Za-z0-9._-]*\.sol$"
_NUMBER = re.compile(
    rb"(?:0x[0-9a-fA-F](?:_?[0-9a-fA-F])*|"
    rb"(?:(?:0|[1-9](?:_?[0-9])*)(?:\.[0-9](?:_?[0-9])*)?|\.[0-9](?:_?[0-9])*)"
    rb"(?:[eE][+-]?[0-9](?:_?[0-9])*)?)"
)
_QUALIFIERS = frozenset(
    {"public", "private", "internal", "external", "pure", "view", "payable", "virtual"}
)
_LOCATIONS = frozenset({"memory", "storage", "calldata"})
_VARIABLE_ATTRIBUTES = frozenset({"public", "private", "internal", "constant", "immutable"})
_UNITS = frozenset({"wei", "gwei", "ether", "seconds", "minutes", "hours", "days", "weeks"})
_RESERVED = frozenset(
    {
        "abstract",
        "assembly",
        "break",
        "catch",
        "constant",
        "constructor",
        "continue",
        "contract",
        "delete",
        "do",
        "else",
        "emit",
        "enum",
        "error",
        "event",
        "external",
        "false",
        "for",
        "function",
        "if",
        "immutable",
        "import",
        "indexed",
        "interface",
        "internal",
        "is",
        "library",
        "mapping",
        "memory",
        "modifier",
        "new",
        "override",
        "pragma",
        "private",
        "public",
        "pure",
        "receive",
        "return",
        "returns",
        "storage",
        "struct",
        "throw",
        "true",
        "try",
        "type",
        "unchecked",
        "using",
        "view",
        "virtual",
        "while",
        "calldata",
        "fallback",
    }
)
_PRECEDENCE = {
    "=": 1,
    "+=": 1,
    "-=": 1,
    "*=": 1,
    "/=": 1,
    "%=": 1,
    "|=": 1,
    "&=": 1,
    "^=": 1,
    "<<=": 1,
    ">>=": 1,
    "||": 3,
    "&&": 4,
    "|": 5,
    "^": 6,
    "&": 7,
    "==": 8,
    "!=": 8,
    "<": 9,
    ">": 9,
    "<=": 9,
    ">=": 9,
    "<<": 10,
    ">>": 10,
    "+": 11,
    "-": 11,
    "*": 12,
    "/": 12,
    "%": 12,
    "**": 13,
}
type SyntaxCallKind = Literal[
    "EXPRESSION",
    "CREATION",
    "INHERITANCE_ARGUMENTS",
    "MODIFIER_ARGUMENTS",
    "EVENT",
    "ERROR",
    "IMPLICIT_MODIFIER",
]


class DependencySyntaxGap(_Record):
    source: str = Field(pattern=_PATH, max_length=512)
    byte_start: int = Field(ge=0, le=262_144)
    byte_end: int = Field(ge=0, le=262_144)
    failure_byte_offset: int = Field(ge=0, le=262_144)
    reason: Literal[
        "UNSUPPORTED_OR_MALFORMED_SYNTAX",
        "UNSUPPORTED_PRAGMA",
        "UNSUPPORTED_TYPE",
        "UNSUPPORTED_ASSEMBLY",
        "UNSUPPORTED_USING",
        "INVALID_STRING_LITERAL",
        "LEXICAL_ERROR",
    ]

    @model_validator(mode="after")
    def exact_span(self) -> Self:
        if not self.byte_start <= self.failure_byte_offset <= self.byte_end:
            raise ValueError("syntax failure leaves its unparsed source suffix")
        return self


class DependencySourceSyntax(_Record):
    source: str = Field(pattern=_PATH, max_length=512)
    source_sha256: str = Field(pattern=_SHA)
    source_bytes: int = Field(gt=0, le=262_144)
    token_count: int = Field(ge=0, le=131_072)
    parsed_token_count: int = Field(ge=0, le=131_072)
    syntax_coverage: Literal["SUPPORTED_GRAMMAR_ACCOUNTED", "NOT_ESTABLISHED"]


class DependencySyntaxCall(_Record):
    source: str = Field(pattern=_PATH, max_length=512)
    byte_start: int = Field(ge=0, lt=262_144)
    call_byte_start: int = Field(gt=0, lt=262_144)
    byte_end: int = Field(gt=0, le=262_144)
    kind: SyntaxCallKind
    typed_call_index: int | None = Field(ge=0, lt=MAX_TARGET_RECORDS)
    typed_match: Literal["EXACT_SPAN", "SPAN_MISMATCH", "MISSING_TYPED_CALL"]

    @model_validator(mode="after")
    def exact_span_and_join(self) -> Self:
        if not self.byte_start <= self.call_byte_start < self.byte_end or (
            (self.byte_start == self.call_byte_start) != (self.kind == "IMPLICIT_MODIFIER")
        ):
            raise ValueError("syntax call opening leaves its span")
        if (self.typed_call_index is None) != (self.typed_match == "MISSING_TYPED_CALL"):
            raise ValueError("syntax call match differs from its typed identity")
        return self


class DependencySyntaxContext(_Record):
    policy: Literal[
        "SOURCE_GRAMMAR_AND_TYPED_CALL_CENSUS_V1",
        "SOURCE_GRAMMAR_AND_MODIFIER_CENSUS_V2",
        "SOURCE_GRAMMAR_AND_CONSTRUCTOR_CENSUS_V3",
    ] = "SOURCE_GRAMMAR_AND_TYPED_CALL_CENSUS_V1"
    scope: Literal["SUPPORTED_SYNTAX_NOT_TYPECHECK_COMPILATION_OR_CALL_CLOSURE"] = (
        "SUPPORTED_SYNTAX_NOT_TYPECHECK_COMPILATION_OR_CALL_CLOSURE"
    )
    source_inventory_sha256: str = Field(pattern=_SHA)
    call_context_sha256: str = Field(pattern=_SHA)
    sources: tuple[DependencySourceSyntax, ...] = Field(min_length=1, max_length=256)
    calls: tuple[DependencySyntaxCall, ...] = Field(max_length=MAX_TARGET_RECORDS)
    gaps: tuple[DependencySyntaxGap, ...] = Field(max_length=256)
    unmatched_typed_call_indices: tuple[int, ...] = Field(max_length=MAX_TARGET_RECORDS)
    complete_static_resolution: Literal[False] = False

    @field_validator("complete_static_resolution", mode="before")
    @classmethod
    def no_complete_resolution(cls, value: object) -> Literal[False]:
        if value is not False:
            raise ValueError("syntax accounting does not establish complete static resolution")
        return False

    @model_validator(mode="after")
    def exact_population(self) -> Self:
        paths = tuple(s.source for s in self.sources)
        if self.policy == "SOURCE_GRAMMAR_AND_TYPED_CALL_CENSUS_V1" and any(
            c.kind == "IMPLICIT_MODIFIER" for c in self.calls
        ):
            raise ValueError("implicit modifiers require their versioned syntax policy")
        gap_paths = tuple(g.source for g in self.gaps)
        identities = tuple((c.source, c.call_byte_start) for c in self.calls)
        if paths != tuple(sorted(set(paths))) or gap_paths != tuple(sorted(set(gap_paths))):
            raise ValueError("syntax source/gap population must be sorted and unique")
        if not set(gap_paths) <= set(paths) or identities != tuple(sorted(set(identities))):
            raise ValueError("syntax call/gap population differs")
        sources = {s.source: s for s in self.sources}
        if self.source_inventory_sha256 != canonical_sha256(
            [
                {"filename": s.source, "sha256": s.source_sha256, "size": s.source_bytes}
                for s in self.sources
            ]
        ):
            raise ValueError("syntax source inventory digest differs")
        for source in self.sources:
            complete = source.source not in gap_paths
            if (source.syntax_coverage == "SUPPORTED_GRAMMAR_ACCOUNTED") != complete or (
                source.parsed_token_count > source.token_count
                or (complete and source.parsed_token_count != source.token_count)
            ):
                raise ValueError("syntax coverage differs from its exact parse shortfalls")
        if any(g.byte_end != sources[g.source].source_bytes for g in self.gaps):
            raise ValueError("syntax gap omits its unparsed source suffix")
        if any(
            c.source not in sources or c.byte_end > sources[c.source].source_bytes
            for c in self.calls
        ):
            raise ValueError("syntax call leaves its source universe")
        joined = [c.typed_call_index for c in self.calls if c.typed_call_index is not None]
        unmatched = self.unmatched_typed_call_indices
        if (
            len(joined) != len(set(joined))
            or unmatched != tuple(sorted(set(unmatched)))
            or (
                any(i < 0 or i >= MAX_TARGET_RECORDS for i in unmatched)
                or set(joined) & set(unmatched)
            )
        ):
            raise ValueError("syntax typed-call identities overlap or repeat")
        if len(self.model_dump_json().encode()) > MAX_TARGET_CONTEXT_BYTES:
            raise ValueError("complete syntax context exceeds its byte ceiling")
        return self

    def validate_call_context(self, context: DependencyCallContext) -> None:
        """Compare the entire typed population, including extra and mismatched calls."""
        if (
            self.policy
            != {
                "SOURCE_ARGUMENT_RETURN_CALL_RESOLUTION_V1": "SOURCE_GRAMMAR_AND_TYPED_CALL_CENSUS_V1",
                "SOURCE_CALL_AND_MODIFIER_RESOLUTION_V2": "SOURCE_GRAMMAR_AND_MODIFIER_CENSUS_V2",
                "SOURCE_CALL_MODIFIER_AND_CONSTRUCTOR_RESOLUTION_V3": "SOURCE_GRAMMAR_AND_CONSTRUCTOR_CENSUS_V3",
            }[context.policy]
        ):
            raise ValueError("syntax and typed modifier policies differ")
        if self.call_context_sha256 != canonical_sha256(context.model_dump(mode="json")) or (
            self.source_inventory_sha256 != context.source_inventory_sha256
            or tuple(s.source for s in self.sources) != tuple(p.primary for p in context.primaries)
        ):
            raise ValueError("syntax context differs from its complete typed source context")
        lookup = {(c.source, c.call_byte_start): i for i, c in enumerate(context.calls)}
        used = set()
        for call in self.calls:
            index = lookup.get((call.source, call.call_byte_start))
            match = "MISSING_TYPED_CALL"
            if index is not None:
                used.add(index)
                typed = context.calls[index]
                match = (
                    "EXACT_SPAN"
                    if (call.byte_start, call.byte_end) == (typed.byte_start, typed.byte_end)
                    else "SPAN_MISMATCH"
                )
            if (call.typed_call_index, call.typed_match) != (index, match):
                raise ValueError("syntax call differs from its exact typed-call join")
        if self.unmatched_typed_call_indices != tuple(
            i for i in range(len(context.calls)) if i not in used
        ):
            raise ValueError("syntax evidence omits unmatched typed calls")


class _SyntaxFailure(Exception):
    def __init__(self, reason: str = "UNSUPPORTED_OR_MALFORMED_SYNTAX") -> None:
        self.reason = reason


class _Parser:
    def __init__(
        self,
        raw: bytes,
        tokens: tuple[_Token, ...],
        work: list[int],
        *,
        include_modifiers: bool = False,
    ) -> None:
        self.raw, self.tokens, self.work = raw, tokens, work
        self.include_modifiers = include_modifiers
        self.i = 0
        self.calls: list[tuple[int, int, int, SyntaxCallKind]] = []

    def charge(self, depth: int = 0) -> None:
        self.work[0] += 1
        if self.work[0] > MAX_SYNTAX_WORK or depth > MAX_SYNTAX_DEPTH:
            raise ValueError("complete syntax accounting exceeds its work/depth ceiling")

    def at(self, value: str, offset: int = 0) -> bool:
        self.charge()
        index = self.i + offset
        return (
            index < len(self.tokens)
            and self.tokens[index].value == value
            and (
                self.tokens[index].kind
                == ("identifier" if value[0].isalpha() or value[0] in "_$" else "punctuation")
            )
        )

    def accept(self, value: str) -> bool:
        if not self.at(value):
            return False
        self.i += 1
        return True

    def expect(self, value: str) -> None:
        if not self.accept(value):
            raise _SyntaxFailure()

    def identifier(self, *, type_name: bool = False) -> None:
        self.charge()
        if (
            self.i >= len(self.tokens)
            or self.tokens[self.i].kind != "identifier"
            or (self.tokens[self.i].value in _RESERVED and not type_name)
        ):
            raise _SyntaxFailure()
        self.i += 1

    def qualified(self) -> None:
        self.identifier()
        while self.accept("."):
            self.identifier()

    def operator(self) -> str:
        self.charge()
        value = ""
        end = self.tokens[self.i].start if self.i < len(self.tokens) else -1
        for token in self.tokens[self.i : self.i + 3]:
            if token.kind != "punctuation" or token.start != end:
                break
            value += token.value
            end = token.end
        return next(
            (
                value[:n]
                for n in (3, 2, 1)
                if value[:n] in {*_PRECEDENCE, "++", "--", "!", "~", "?"}
            ),
            "",
        )

    def type_name(self, depth: int) -> None:
        self.charge(depth)
        if self.at("mapping") or self.at("function"):
            raise _SyntaxFailure("UNSUPPORTED_TYPE")
        if self.i >= len(self.tokens) or self.tokens[self.i].value in _RESERVED:
            raise _SyntaxFailure("UNSUPPORTED_TYPE")
        address = self.at("address")
        self.qualified()
        if address:
            self.accept("payable")
        while self.accept("["):
            if not self.at("]"):
                self.expression(depth + 1)
            self.expect("]")

    def parameters(self, depth: int, *, indexed: bool = False) -> None:
        self.expect("(")
        if self.accept(")"):
            return
        count = 0
        while True:
            count += 1
            if count > 64:
                raise ValueError("complete syntax parameter list exceeds its bound")
            self.type_name(depth + 1)
            if self.i < len(self.tokens) and self.tokens[self.i].value in _LOCATIONS:
                self.i += 1
            if indexed:
                self.accept("indexed")
            if not self.at(",") and not self.at(")"):
                self.identifier()
            if not self.accept(","):
                break
        self.expect(")")

    def arguments(self, start: int, depth: int, kind: SyntaxCallKind) -> None:
        opening = self.i
        self.expect("(")
        if self.accept("{"):
            self.named_expressions(depth + 1)
            self.expect("}")
        elif not self.at(")"):
            self.expression_list(depth + 1, ")")
        self.expect(")")
        self.calls.append(
            (
                self.tokens[start].start,
                self.tokens[opening].start,
                self.tokens[self.i - 1].end,
                kind,
            )
        )
        if len(self.calls) > MAX_TARGET_RECORDS:
            raise ValueError("complete syntax call census exceeds its record ceiling")

    def named_expressions(self, depth: int) -> None:
        seen: set[str] = set()
        while True:
            if self.i >= len(self.tokens):
                raise _SyntaxFailure()
            name = self.tokens[self.i].value
            self.identifier()
            if name in seen or len(seen) >= 64:
                raise _SyntaxFailure()
            seen.add(name)
            self.expect(":")
            self.expression(depth + 1)
            if not self.accept(","):
                break

    def expression_list(self, depth: int, closing: str, *, holes: bool = False) -> None:
        count = 0
        while True:
            count += 1
            if count > 64:
                raise ValueError("complete syntax expression list exceeds its bound")
            if not holes or not (self.at(",") or self.at(closing)):
                self.expression(depth + 1)
            if not self.accept(","):
                break

    def string_literal(self, prefix: str = "") -> None:
        self.charge()
        if self.i >= len(self.tokens) or self.tokens[self.i].kind != "string":
            raise _SyntaxFailure("INVALID_STRING_LITERAL")
        token = self.tokens[self.i]
        value = self.raw[token.start + 1 : token.end - 1]
        valid = True
        if prefix == "hex":
            valid = re.fullmatch(rb"(?:[0-9a-fA-F]{2})*", value) is not None
        else:
            index = 0
            while index < len(value):
                self.charge()
                byte = value[index]
                if byte == 92:
                    index += 1
                    if index >= len(value):
                        valid = False
                        break
                    escape = value[index]
                    width = 2 if escape == ord("x") else 4 if escape == ord("u") else 0
                    if width:
                        digits = value[index + 1 : index + width + 1]
                        valid &= (
                            len(digits) == width
                            and re.fullmatch(rb"[0-9a-fA-F]+", digits) is not None
                        )
                        index += width
                    else:
                        valid &= escape in b"nrt'\"\\"
                else:
                    valid &= byte >= 32 and (prefix == "unicode" or byte < 127)
                index += 1
        if not valid:
            raise _SyntaxFailure("INVALID_STRING_LITERAL")
        self.i += 1

    def expression(self, depth: int, minimum: int = 1, kind: SyntaxCallKind = "EXPRESSION") -> None:
        self.charge(depth)
        start = self.i
        operator = self.operator()
        if operator in {"-", "!", "~", "++", "--"} or self.at("delete"):
            self.i += len(operator) if operator else 1
            self.expression(depth + 1, 14)
        else:
            creation = self.accept("new")
            if creation:
                start = self.i
                self.type_name(depth + 1)
                if not (self.at("(") or self.at("{")):
                    raise _SyntaxFailure()
            elif self.accept("("):
                if not self.at(")"):
                    self.expression_list(depth + 1, ")", holes=True)
                self.expect(")")
            elif self.accept("["):
                if self.at("]"):
                    raise _SyntaxFailure()
                self.expression_list(depth + 1, "]")
                self.expect("]")
            elif self.at("true") or self.at("false"):
                self.i += 1
            elif self.at("unicode") or self.at("hex"):
                prefix = self.tokens[self.i].value
                self.i += 1
                self.string_literal(prefix)
            elif self.i < len(self.tokens) and self.tokens[self.i].kind == "string":
                self.string_literal()
                while self.i < len(self.tokens) and self.tokens[self.i].kind == "string":
                    self.string_literal()
            elif self.i < len(self.tokens) and (
                self.tokens[self.i].value[0].isdigit() or self.at(".")
            ):
                match = _NUMBER.match(self.raw, self.tokens[self.i].start)
                if match is None:
                    raise _SyntaxFailure()
                end = match.end()
                while self.i < len(self.tokens) and self.tokens[self.i].end <= end:
                    self.charge()
                    self.i += 1
                if self.tokens[self.i - 1].end != end:
                    raise _SyntaxFailure()
                if (
                    self.i < len(self.tokens)
                    and self.tokens[self.i].kind == "identifier"
                    and self.tokens[self.i].value in _UNITS
                ):
                    self.i += 1
            elif self.at("type"):
                self.i += 1
            else:
                self.identifier()
            while True:
                self.charge(depth)
                if self.accept("."):
                    self.identifier()
                elif self.accept("["):
                    if not (self.at(":") or self.at("]")):
                        self.expression(depth + 1)
                    if self.accept(":") and not self.at("]"):
                        self.expression(depth + 1)
                    self.expect("]")
                elif self.at("{"):
                    self.i += 1
                    self.named_expressions(depth + 1)
                    self.expect("}")
                    self.arguments(start, depth + 1, "CREATION" if creation else kind)
                    creation = False
                    kind = "EXPRESSION"
                elif self.at("("):
                    self.arguments(start, depth + 1, "CREATION" if creation else kind)
                    creation = False
                    kind = "EXPRESSION"
                elif self.operator() in {"++", "--"}:
                    self.i += 2
                    break
                else:
                    break
        while True:
            operator = self.operator()
            if operator == "?" and minimum <= 2:
                self.i += 1
                self.expression(depth + 1)
                self.expect(":")
                self.expression(depth + 1, 2)
            elif operator in _PRECEDENCE and _PRECEDENCE[operator] >= minimum:
                precedence = _PRECEDENCE[operator]
                self.i += len(operator)
                self.expression(
                    depth + 1, precedence if precedence == 1 or operator == "**" else precedence + 1
                )
            else:
                break

    def looks_like_declaration(self) -> bool:
        self.charge()
        index = self.i
        if index >= len(self.tokens) or self.tokens[index].kind != "identifier":
            return False
        if self.tokens[index].value in _RESERVED:
            return False
        index += 1
        while (
            index + 1 < len(self.tokens)
            and self.tokens[index].kind == "punctuation"
            and self.tokens[index].value == "."
            and self.tokens[index + 1].kind == "identifier"
        ):
            self.charge()
            index += 2
        while (
            index < len(self.tokens)
            and self.tokens[index].kind == "punctuation"
            and self.tokens[index].value == "["
        ):
            nesting = 1
            index += 1
            while index < len(self.tokens) and nesting:
                self.charge()
                token = self.tokens[index]
                if token.kind == "punctuation":
                    nesting += (token.value == "[") - (token.value == "]")
                index += 1
        if (
            index < len(self.tokens)
            and self.tokens[index].kind == "identifier"
            and self.tokens[index].value in {*_LOCATIONS, "payable"}
        ):
            index += 1
        return (
            index < len(self.tokens)
            and self.tokens[index].kind == "identifier"
            and self.tokens[index].value not in _RESERVED
        )

    def variable(self, depth: int, *, state: bool = False) -> None:
        self.type_name(depth + 1)
        attributes = _VARIABLE_ATTRIBUTES if state else _LOCATIONS
        seen = set()
        while (
            self.i < len(self.tokens)
            and self.tokens[self.i].kind == "identifier"
            and self.tokens[self.i].value in attributes
        ):
            attribute = self.tokens[self.i].value
            if attribute in seen:
                raise _SyntaxFailure()
            seen.add(attribute)
            self.i += 1
        self.identifier()
        if self.accept("="):
            self.expression(depth + 1)

    def statement(self, depth: int) -> None:
        self.charge(depth)
        if self.accept("{"):
            while not self.accept("}"):
                self.statement(depth + 1)
        elif self.accept("unchecked"):
            if not self.at("{"):
                raise _SyntaxFailure()
            self.statement(depth + 1)
        elif self.accept("if"):
            self.expect("(")
            self.expression(depth + 1)
            self.expect(")")
            self.statement(depth + 1)
            if self.accept("else"):
                self.statement(depth + 1)
        elif self.accept("while"):
            self.expect("(")
            self.expression(depth + 1)
            self.expect(")")
            self.statement(depth + 1)
        elif self.accept("for"):
            self.expect("(")
            if not self.at(";"):
                self.variable(depth + 1) if self.looks_like_declaration() else self.expression(
                    depth + 1
                )
            self.expect(";")
            if not self.at(";"):
                self.expression(depth + 1)
            self.expect(";")
            if not self.at(")"):
                self.expression(depth + 1)
            self.expect(")")
            self.statement(depth + 1)
        elif self.accept("do"):
            self.statement(depth + 1)
            self.expect("while")
            self.expect("(")
            self.expression(depth + 1)
            self.expect(")")
            self.expect(";")
        elif self.at("try") or self.at("assembly"):
            # try's success block is ambiguous with call-options in a context-free postfix
            # parse. Until its dedicated production exists, retain the whole source suffix.
            raise _SyntaxFailure(
                "UNSUPPORTED_ASSEMBLY" if self.at("assembly") else "UNSUPPORTED_OR_MALFORMED_SYNTAX"
            )
        elif self.accept("return"):
            if not self.at(";"):
                self.expression(depth + 1)
            self.expect(";")
        elif self.accept("break") or self.accept("continue"):
            self.expect(";")
        elif self.accept("emit"):
            start = self.i
            self.qualified()
            self.arguments(start, depth + 1, "EVENT")
            self.expect(";")
        elif self.at("revert") and not self.at("(", 1):
            self.i += 1
            start = self.i
            self.qualified()
            self.arguments(start, depth + 1, "ERROR")
            self.expect(";")
        elif self.accept(";"):
            pass
        else:
            self.variable(depth + 1) if self.looks_like_declaration() else self.expression(
                depth + 1
            )
            self.expect(";")

    def function(self, depth: int) -> None:
        kind = self.tokens[self.i].value
        self.i += 1
        if kind in {"function", "modifier"}:
            self.identifier()
        if kind != "modifier" or self.at("("):
            self.parameters(depth + 1)
        seen = set()
        while not (self.at("{") or self.at(";")):
            self.charge(depth)
            if self.i >= len(self.tokens):
                raise _SyntaxFailure()
            value = self.tokens[self.i].value
            if value in _QUALIFIERS and self.tokens[self.i].kind == "identifier":
                if value in seen:
                    raise _SyntaxFailure()
                seen.add(value)
                self.i += 1
            elif self.accept("returns"):
                if "returns" in seen:
                    raise _SyntaxFailure()
                seen.add("returns")
                self.parameters(depth + 1)
            elif self.accept("override"):
                if "override" in seen:
                    raise _SyntaxFailure()
                seen.add("override")
                if self.accept("("):
                    self.qualified()
                    while self.accept(","):
                        self.qualified()
                    self.expect(")")
            else:
                if self.include_modifiers and kind == "modifier":
                    raise _SyntaxFailure()
                start = self.i
                self.qualified()
                if self.at("("):
                    self.arguments(start, depth + 1, "MODIFIER_ARGUMENTS")
                elif self.include_modifiers:
                    self.calls.append(
                        (
                            self.tokens[start].start,
                            self.tokens[start].start,
                            self.tokens[self.i - 1].end,
                            "IMPLICIT_MODIFIER",
                        )
                    )
                    if len(self.calls) > MAX_TARGET_RECORDS:
                        raise ValueError("complete modifier syntax census exceeds its ceiling")
                else:
                    # An implicit modifier invocation has no opening parenthesis to join.
                    # Until it has dedicated dependency evidence it cannot disappear at EOF.
                    raise _SyntaxFailure()
        if not self.accept(";"):
            self.statement(depth + 1)

    def declaration(self, depth: int = 0, *, in_contract: bool = False) -> None:
        self.charge(depth)
        if not in_contract and self.accept("pragma"):
            self.expect("solidity")
            start = self.i
            while not self.at(";"):
                if self.i >= len(self.tokens):
                    raise _SyntaxFailure("UNSUPPORTED_PRAGMA")
                self.i += 1
                self.charge()
            raw = self.raw[self.tokens[start].start : self.tokens[self.i].start].strip()
            if re.fullmatch(rb"\^?0\.8\.(?:0|[1-9][0-9]?)", raw) is None:
                raise _SyntaxFailure("UNSUPPORTED_PRAGMA")
            self.i += 1
        elif not in_contract and self.accept("import"):
            from mmaudit.solidity.dependency_closure import _import_literal

            start = self.i
            while not self.at(";"):
                if self.i >= len(self.tokens):
                    raise _SyntaxFailure()
                self.i += 1
                self.charge()
            if _import_literal(self.tokens[start : self.i]) is None:
                raise _SyntaxFailure()
            self.i += 1
        elif not in_contract and (
            self.at("abstract") or self.at("contract") or self.at("interface") or self.at("library")
        ):
            abstract = self.accept("abstract")
            if abstract:
                self.expect("contract")
            else:
                self.i += 1
            self.identifier()
            if self.accept("is"):
                while True:
                    start = self.i
                    self.qualified()
                    if self.at("("):
                        self.arguments(start, depth + 1, "INHERITANCE_ARGUMENTS")
                    if not self.accept(","):
                        break
            self.expect("{")
            while not self.accept("}"):
                self.declaration(depth + 1, in_contract=True)
        elif any(
            self.at(word) for word in ("function", "constructor", "modifier", "fallback", "receive")
        ):
            self.function(depth + 1)
        elif self.accept("event"):
            self.identifier()
            self.parameters(depth + 1, indexed=True)
            self.accept("anonymous")
            self.expect(";")
        elif self.accept("error"):
            self.identifier()
            self.parameters(depth + 1)
            self.expect(";")
        elif self.accept("struct"):
            self.identifier()
            self.expect("{")
            while not self.accept("}"):
                self.type_name(depth + 1)
                self.identifier()
                self.expect(";")
        elif self.accept("enum"):
            self.identifier()
            self.expect("{")
            self.identifier()
            while self.accept(","):
                self.identifier()
            self.expect("}")
        elif self.accept("type"):
            self.identifier()
            self.expect("is")
            self.type_name(depth + 1)
            self.expect(";")
        elif self.at("using"):
            raise _SyntaxFailure("UNSUPPORTED_USING")
        else:
            self.variable(depth + 1, state=True)
            self.expect(";")


def build_dependency_syntax_context(
    *, source_files: tuple[tuple[str, bytes], ...], call_context: DependencyCallContext
) -> DependencySyntaxContext:
    """Account for exact supplied syntax; retain every parse/census failure, without I/O."""
    from mmaudit.solidity.dependency_closure import DependencySource, _tokens

    if type(source_files) is not tuple or not 1 <= len(source_files) <= 256:
        raise ValueError("syntax accounting requires bounded immutable sources")
    if any(
        type(pair) is not tuple
        or len(pair) != 2
        or type(pair[0]) is not str
        or type(pair[1]) is not bytes
        for pair in source_files
    ):
        raise ValueError("syntax accounting requires exact immutable source pairs")
    inventory = tuple(
        DependencySource(filename=path, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
        for path, raw in source_files
    )
    paths = tuple(s.filename for s in inventory)
    if (
        paths != tuple(sorted(set(paths)))
        or len({p.casefold() for p in paths}) != len(paths)
        or sum(s.size for s in inventory) > 8_388_608
    ):
        raise ValueError("syntax source universe exceeds its exact bounded scope")
    inventory_sha = canonical_sha256([s.model_dump(mode="json") for s in inventory])
    if inventory_sha != call_context.source_inventory_sha256:
        raise ValueError("syntax source bytes differ from their typed inventory")
    sources: list[DependencySourceSyntax] = []
    gaps: list[DependencySyntaxGap] = []
    calls: list[DependencySyntaxCall] = []
    lookup = {(c.source, c.call_byte_start): i for i, c in enumerate(call_context.calls)}
    used: set[int] = set()
    work = [0]
    for source, (_, raw) in zip(inventory, source_files, strict=True):
        raw.decode("utf-8")
        tokens, lexical_error = _tokens(raw)
        parser = _Parser(
            raw,
            tokens,
            work,
            include_modifiers=call_context.policy != "SOURCE_ARGUMENT_RETURN_CALL_RESOLUTION_V1",
        )
        parsed = 0
        reason: str | None = None
        failure = lexical_error
        try:
            while parser.i < len(tokens):
                parser.declaration()
                if parser.i <= parsed:
                    raise ValueError("syntax parser did not advance")
                parsed = parser.i
        except _SyntaxFailure as error:
            reason = error.reason
            failure = tokens[parser.i].start if parser.i < len(tokens) else len(raw)
        if lexical_error is not None and reason is None:
            reason = "LEXICAL_ERROR"
        if reason is not None:
            gaps.append(
                DependencySyntaxGap.model_validate(
                    {
                        "source": source.filename,
                        "byte_start": tokens[parsed].start
                        if parsed < len(tokens)
                        else (lexical_error if lexical_error is not None else len(raw)),
                        "byte_end": len(raw),
                        "failure_byte_offset": failure,
                        "reason": reason,
                    }
                )
            )
        sources.append(
            DependencySourceSyntax(
                source=source.filename,
                source_sha256=source.sha256,
                source_bytes=source.size,
                token_count=len(tokens),
                parsed_token_count=parsed,
                syntax_coverage="SUPPORTED_GRAMMAR_ACCOUNTED"
                if reason is None
                else "NOT_ESTABLISHED",
            )
        )
        for start, opening, end, kind in sorted(parser.calls, key=lambda item: item[1]):
            index = lookup.get((source.filename, opening))
            match: Literal["EXACT_SPAN", "SPAN_MISMATCH", "MISSING_TYPED_CALL"] = (
                "MISSING_TYPED_CALL"
            )
            if index is not None:
                used.add(index)
                typed = call_context.calls[index]
                match = (
                    "EXACT_SPAN"
                    if (start, end) == (typed.byte_start, typed.byte_end)
                    else "SPAN_MISMATCH"
                )
            calls.append(
                DependencySyntaxCall(
                    source=source.filename,
                    byte_start=start,
                    call_byte_start=opening,
                    byte_end=end,
                    kind=kind,
                    typed_call_index=index,
                    typed_match=match,
                )
            )
        if len(calls) > MAX_TARGET_RECORDS:
            raise ValueError("complete syntax call census exceeds its record ceiling")
    context = DependencySyntaxContext(
        policy="SOURCE_GRAMMAR_AND_CONSTRUCTOR_CENSUS_V3"
        if call_context.policy == "SOURCE_CALL_MODIFIER_AND_CONSTRUCTOR_RESOLUTION_V3"
        else "SOURCE_GRAMMAR_AND_MODIFIER_CENSUS_V2"
        if call_context.policy == "SOURCE_CALL_AND_MODIFIER_RESOLUTION_V2"
        else "SOURCE_GRAMMAR_AND_TYPED_CALL_CENSUS_V1",
        source_inventory_sha256=inventory_sha,
        call_context_sha256=canonical_sha256(call_context.model_dump(mode="json")),
        sources=tuple(sources),
        calls=tuple(calls),
        gaps=tuple(gaps),
        unmatched_typed_call_indices=tuple(
            i for i in range(len(call_context.calls)) if i not in used
        ),
    )
    context.validate_call_context(call_context)
    return context
