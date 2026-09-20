"""Source-bound declaration/implementation context, not Solidity type checking or call closure.

The name policy is deliberately conservative. Unsupported namespaces and possible
shadowing retain shortfalls; expression spellings never become implementation identities.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.orchestration.manifest import canonical_sha256

if TYPE_CHECKING:
    from mmaudit.solidity.dependency_closure import DependencyImport, DependencyParseGap, _Token

MAX_TARGET_RECORDS = 4096
MAX_TARGET_WORK = 1_000_000
# Retain bounded declaration evidence for the full admitted 256-source population.
MAX_TARGET_CONTEXT_BYTES = 2_097_152
_SHA = r"^[0-9a-f]{64}$"
_PATH = r"^(?:[A-Za-z0-9][A-Za-z0-9._-]*/)*[A-Za-z0-9][A-Za-z0-9._-]*\.sol$"
_IDENTIFIER = r"^[A-Za-z_$][A-Za-z0-9_$]*$"
_LOW_LEVEL = frozenset({"call", "staticcall", "delegatecall", "callcode", "send", "transfer"})


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class DependencyTypeDeclaration(_Record):
    id: str = Field(pattern=_SHA)
    source: str = Field(pattern=_PATH, max_length=512)
    source_sha256: str = Field(pattern=_SHA)
    name: str = Field(pattern=_IDENTIFIER, max_length=512)
    kind: Literal["contract", "interface", "library"]
    abstract: bool
    byte_start: int = Field(ge=0, lt=262_144)
    byte_end: int = Field(gt=0, le=262_144)

    @model_validator(mode="after")
    def exact_identity(self) -> Self:
        if self.byte_end <= self.byte_start or self.id != canonical_sha256(
            self.model_dump(mode="json", exclude={"id"})
        ):
            raise ValueError("dependency type declaration identity differs")
        return self


class DependencyTypeBinding(_Record):
    source: str = Field(pattern=_PATH, max_length=512)
    byte_start: int = Field(ge=0, lt=262_144)
    spelling: str = Field(min_length=1, max_length=512)
    candidate_ids: tuple[str, ...] = Field(max_length=MAX_TARGET_RECORDS)
    target_id: str | None = Field(default=None, pattern=_SHA)
    shortfall: str | None = Field(default=None, pattern=r"^[A-Z_]+$", max_length=128)

    @model_validator(mode="after")
    def unique_or_unresolved(self) -> Self:
        if self.candidate_ids != tuple(sorted(set(self.candidate_ids))):
            raise ValueError("type binding candidates must be exact and unique")
        if (self.target_id is None) != (self.shortfall is not None):
            raise ValueError("type binding must resolve or retain a shortfall")
        if self.target_id is not None and self.candidate_ids != (self.target_id,):
            raise ValueError("type binding must not select one ambiguous declaration")
        return self


class DependencyInheritanceBinding(_Record):
    inheritor_id: str = Field(pattern=_SHA)
    base: DependencyTypeBinding


class DependencyCallBinding(_Record):
    source: str = Field(pattern=_PATH, max_length=512)
    byte_start: int = Field(ge=0, lt=262_144)
    byte_end: int = Field(gt=0, le=262_144)
    member: str = Field(pattern=_IDENTIFIER, max_length=512)
    receiver_form: Literal["TYPE_CAST", "TYPE_MEMBER", "UNSUPPORTED_EXPRESSION"]
    receiver: DependencyTypeBinding
    implementation_ids: tuple[str, ...] = Field(max_length=MAX_TARGET_RECORDS)
    shortfalls: tuple[str, ...] = Field(max_length=32)
    member_dispatch: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"


class DependencyTargetGap(_Record):
    source: str = Field(pattern=_PATH, max_length=512)
    byte_start: int = Field(ge=0, lt=262_144)
    reason: str = Field(pattern=r"^[A-Z_]+$", max_length=128)


class DependencyTargetMembers(_Record):
    primary: str = Field(pattern=_PATH, max_length=512)
    members: tuple[str, ...] = Field(min_length=1, max_length=256)
    unresolved_call_indices: tuple[int, ...] = Field(max_length=MAX_TARGET_RECORDS)
    gap_indices: tuple[int, ...] = Field(max_length=MAX_TARGET_RECORDS)


class DependencyTargetContext(_Record):
    policy: Literal["SOURCE_NAMESPACE_AND_EXPLICIT_TYPE_RECEIVERS_V1"] = (
        "SOURCE_NAMESPACE_AND_EXPLICIT_TYPE_RECEIVERS_V1"
    )
    scope: Literal["SUPPLIED_DECLARATIONS_NOT_FILESYSTEM_OR_DEPLOYMENT_COMPLETENESS"] = (
        "SUPPLIED_DECLARATIONS_NOT_FILESYSTEM_OR_DEPLOYMENT_COMPLETENESS"
    )
    source_inventory_sha256: str = Field(pattern=_SHA)
    declarations: tuple[DependencyTypeDeclaration, ...] = Field(max_length=MAX_TARGET_RECORDS)
    inheritance: tuple[DependencyInheritanceBinding, ...] = Field(max_length=MAX_TARGET_RECORDS)
    calls: tuple[DependencyCallBinding, ...] = Field(max_length=MAX_TARGET_RECORDS)
    gaps: tuple[DependencyTargetGap, ...] = Field(max_length=MAX_TARGET_RECORDS)
    primaries: tuple[DependencyTargetMembers, ...] = Field(min_length=1, max_length=256)
    solidity_typecheck: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    complete_static_resolution: Literal[False] = False

    @field_validator("complete_static_resolution", mode="before")
    @classmethod
    def no_complete_resolution(cls, value: object) -> Literal[False]:
        if value is not False:
            raise ValueError("declaration bindings cannot claim complete static resolution")
        return False

    @model_validator(mode="after")
    def exact_membership(self) -> Self:
        ids = {d.id for d in self.declarations}
        paths = tuple(p.primary for p in self.primaries)
        if len(ids) != len(self.declarations) or paths != tuple(sorted(set(paths))):
            raise ValueError("target context duplicates a source or declaration")
        bindings = [i.base for i in self.inheritance] + [c.receiver for c in self.calls]
        if any(b.source not in paths or not set(b.candidate_ids) <= ids for b in bindings):
            raise ValueError("target binding leaves its supplied source/type universe")
        if any(i.inheritor_id not in ids for i in self.inheritance) or any(
            d.source not in paths for d in self.declarations
        ):
            raise ValueError("target declaration or inheritance has no supplied source")
        if any(g.source not in paths for g in self.gaps):
            raise ValueError("target gap has no supplied source")
        for call in self.calls:
            if (
                call.source != call.receiver.source
                or call.byte_end <= call.byte_start
                or call.implementation_ids != tuple(sorted(set(call.implementation_ids)))
                or not set(call.implementation_ids) <= ids
            ):
                raise ValueError("target call binding or implementation membership differs")
        for primary in self.primaries:
            if (
                primary.members != tuple(sorted(set(primary.members)))
                or primary.primary not in primary.members
                or not set(primary.members) <= set(paths)
                or any(not 0 <= i < len(self.calls) for i in primary.unresolved_call_indices)
                or any(not 0 <= i < len(self.gaps) for i in primary.gap_indices)
            ):
                raise ValueError("target primary context or shortfall membership differs")
        if len(self.model_dump_json().encode()) > MAX_TARGET_CONTEXT_BYTES:
            raise ValueError("complete target context exceeds its byte ceiling")
        return self


@dataclass
class _Unit:
    tokens: tuple[_Token, ...]
    pairs: dict[int, int]
    declarations: list[DependencyTypeDeclaration]
    bases: list[tuple[str, int, str]]
    imports: list[tuple[DependencyImport, tuple[_Token, ...]]]
    excluded: set[int]
    unsafe: bool = False


def _qualified(tokens: tuple[_Token, ...]) -> str | None:
    if not tokens or len(tokens) % 2 == 0:
        return None
    if any(
        t.kind != "identifier" if i % 2 == 0 else t.kind != "punctuation" or t.value != "."
        for i, t in enumerate(tokens)
    ):
        return None
    return ".".join(t.value for t in tokens[::2])


def _qualified_before(tokens: tuple[_Token, ...], end: int) -> tuple[int, str | None]:
    start = end - 1
    if start < 0 or tokens[start].kind != "identifier":
        return end, None
    while start >= 2 and tokens[start - 1].value == "." and tokens[start - 2].kind == "identifier":
        start -= 2
    return start, _qualified(tokens[start:end])


def _unit(
    source: str,
    content: bytes,
    imports: tuple[DependencyImport, ...],
    gaps: list[DependencyTargetGap],
) -> _Unit:
    # Lazy import shares the exact existing lexer without a module-initialization cycle.
    import hashlib

    from mmaudit.solidity.dependency_closure import _tokens

    tokens, failure = _tokens(content)
    unit = _Unit(tokens, {}, [], [], [], set())

    def gap(offset: int, reason: str) -> None:
        unit.unsafe = True
        gaps.append(DependencyTargetGap(source=source, byte_start=offset, reason=reason))
        if len(gaps) > MAX_TARGET_RECORDS:
            raise ValueError("complete target parse gaps exceed their record ceiling")

    if failure is not None:
        gap(failure, "SOURCE_LEXICAL_ERROR")
    stack: list[int] = []
    closes = {"}": "{", ")": "(", "]": "["}
    for i, token in enumerate(tokens):
        if token.kind != "punctuation":
            continue
        if token.value in {"{", "(", "["}:
            stack.append(i)
        elif token.value in closes:
            if not stack or tokens[stack[-1]].value != closes[token.value]:
                gap(token.start, "SOURCE_DELIMITER_ERROR")
            else:
                other = stack.pop()
                unit.pairs[i] = other
                unit.pairs[other] = i
    for i in stack:
        gap(tokens[i].start, "SOURCE_DELIMITER_ERROR")
    by_start = {item.byte_start: item for item in imports if item.source == source}
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.kind == "identifier" and token.value in {"import", "pragma"}:
            end = i + 1
            while end < len(tokens) and not (
                tokens[end].kind == "punctuation" and tokens[end].value == ";"
            ):
                end += 1
            if end == len(tokens):
                gap(token.start, "UNTERMINATED_TOP_LEVEL_DIRECTIVE")
                break
            unit.excluded.update(range(i, end + 1))
            if token.value == "import":
                imported = by_start.get(token.start)
                if imported is None or imported.shortfall is not None:
                    gap(token.start, "IMPORT_TARGET_NOT_RESOLVED")
                else:
                    unit.imports.append((imported, tokens[i + 1 : end]))
            i = end + 1
            continue
        begin = i
        abstract = token.kind == "identifier" and token.value == "abstract"
        if abstract:
            i += 1
        if (
            i + 1 >= len(tokens)
            or tokens[i].kind != "identifier"
            or tokens[i].value not in {"contract", "interface", "library"}
            or tokens[i + 1].kind != "identifier"
        ):
            gap(token.start, "UNSUPPORTED_TOP_LEVEL_DECLARATION")
            # Skip one complete top-level statement/body, retaining the whole-file shortfall.
            i = begin + 1
            while i < len(tokens) and tokens[i].value not in {";", "{"}:
                i += 1
            i = unit.pairs.get(i, i) + 1
            continue
        kind = tokens[i].value
        if abstract and kind != "contract":
            gap(token.start, "UNSUPPORTED_TYPE_HEADER")
        name = tokens[i + 1].value
        body = i + 2
        while body < len(tokens) and tokens[body].value not in {"{", ";"}:
            body = (
                unit.pairs[body] + 1
                if tokens[body].value == "(" and body in unit.pairs
                else body + 1
            )
        if body >= len(tokens) or tokens[body].value != "{" or body not in unit.pairs:
            gap(token.start, "TYPE_BODY_NOT_PARSED")
            break
        end = unit.pairs[body]
        values = dict(
            source=source,
            source_sha256=hashlib.sha256(content).hexdigest(),
            name=name,
            kind=kind,
            abstract=abstract,
            byte_start=tokens[begin].start,
            byte_end=tokens[end].end,
        )
        declaration = DependencyTypeDeclaration.model_validate(
            {**values, "id": canonical_sha256(values)}
        )
        unit.declarations.append(declaration)
        unit.excluded.update(range(begin, body + 1))
        cursor = i + 2
        if cursor < body:
            if tokens[cursor].value != "is" or kind == "library":
                gap(tokens[cursor].start, "UNSUPPORTED_TYPE_HEADER")
            else:
                cursor += 1
                while cursor < body:
                    first = cursor
                    while cursor < body and tokens[cursor].value not in {",", "("}:
                        cursor += 1
                    spelling = _qualified(tokens[first:cursor])
                    if spelling is None:
                        gap(tokens[first].start, "UNSUPPORTED_BASE_TYPE")
                        break
                    unit.bases.append((declaration.id, tokens[first].start, spelling))
                    if cursor < body and tokens[cursor].value == "(":
                        if cursor not in unit.pairs:
                            gap(tokens[cursor].start, "UNSUPPORTED_BASE_ARGUMENTS")
                            break
                        cursor = unit.pairs[cursor] + 1
                    if cursor < body:
                        if tokens[cursor].value != "," or cursor + 1 == body:
                            gap(tokens[cursor].start, "UNSUPPORTED_BASE_TYPE")
                            break
                        cursor += 1
        i = end + 1
    return unit


def _source_names(
    units: dict[str, _Unit],
    declarations: tuple[DependencyTypeDeclaration, ...],
    gaps: list[DependencyTargetGap],
) -> tuple[dict[str, dict[str, set[str]]], set[str], int]:
    """Resolve the same bounded import namespace for legacy and scoped consumers."""

    names: dict[str, dict[str, set[str]]] = {p: {} for p in units}
    for declaration in declarations:
        names[declaration.source].setdefault(declaration.name, set()).add(declaration.id)
    unsafe = {p for p, u in units.items() if u.unsafe}
    work = 0
    for _ in range(MAX_TARGET_RECORDS):
        changed = False
        for source, unit in units.items():
            for imported, tokens in unit.imports:
                target = imported.target
                if target not in units:
                    raise ValueError("target import computation leaves supplied sources")
                if target in unsafe and source not in unsafe:
                    unsafe.add(source)
                    changed = True
                additions: list[tuple[str, set[str]]] = []
                if tokens[0].kind == "string":
                    prefix = "" if len(tokens) == 1 else tokens[2].value + "."
                    additions = [(prefix + name, set(ids)) for name, ids in names[target].items()]
                elif tokens[0].value == "*":
                    additions = [
                        (tokens[2].value + "." + name, set(ids))
                        for name, ids in names[target].items()
                    ]
                elif tokens[0].value == "{":
                    cursor = 1
                    while cursor < len(tokens) and tokens[cursor].value != "}":
                        original = tokens[cursor].value
                        alias = original
                        cursor += 1
                        if tokens[cursor].value == "as":
                            alias = tokens[cursor + 1].value
                            cursor += 2
                        additions.append((alias, set(names[target].get(original, ()))))
                        if tokens[cursor].value == ",":
                            cursor += 1
                for name, ids in additions:
                    work += 1 + len(ids)
                    if work > MAX_TARGET_WORK or len(name) > 512:
                        raise ValueError("complete namespace resolution exceeds its work ceiling")
                    selected = names[source].setdefault(name, set())
                    if not ids <= selected:
                        selected.update(ids)
                        changed = True
                if sum(len(v) for v in names[source].values()) > MAX_TARGET_RECORDS:
                    raise ValueError("complete namespace bindings exceed their record ceiling")
        if not changed:
            break
    else:
        raise ValueError("namespace resolution did not reach a bounded fixed point")
    for source, environment in names.items():
        for ids in environment.values():
            if not ids:
                gaps.append(
                    DependencyTargetGap(
                        source=source, byte_start=0, reason="IMPORT_SYMBOL_NOT_RESOLVED"
                    )
                )
                unsafe.add(source)
    # A missing selected symbol makes downstream imported namespaces incomplete too.
    for _ in units:
        inherited = {
            source
            for source, unit in units.items()
            if any(imported.target in unsafe for imported, _ in unit.imports)
        }
        if inherited <= unsafe:
            break
        unsafe.update(inherited)
    return names, unsafe, work


def build_dependency_target_context(
    *,
    source_files: tuple[tuple[str, bytes], ...],
    imports: tuple[DependencyImport, ...],
    source_inventory_sha256: str,
    parse_gaps: tuple[DependencyParseGap, ...] = (),
    unsupported_remapping_lines: tuple[int, ...] = (),
) -> DependencyTargetContext:
    """Build from an already source-validated import computation; consumers recompute both."""

    if not 1 <= len(source_files) <= 256 or len(imports) > MAX_TARGET_RECORDS:
        raise ValueError("target source/import universe exceeds its bounds")
    gaps: list[DependencyTargetGap] = []
    units = {source: _unit(source, raw, imports, gaps) for source, raw in source_files}
    for gap in parse_gaps:
        if gap.source not in units:
            raise ValueError("import parse gap leaves supplied target sources")
        units[gap.source].unsafe = True
        gaps.append(
            DependencyTargetGap(source=gap.source, byte_start=gap.byte_offset, reason=gap.reason)
        )
    if unsupported_remapping_lines:
        for source, unit in units.items():
            unit.unsafe = True
            gaps.append(
                DependencyTargetGap(
                    source=source, byte_start=0, reason="IMPORT_POLICY_NOT_ESTABLISHED"
                )
            )
    if len(gaps) > MAX_TARGET_RECORDS:
        raise ValueError("complete target parse gaps exceed their record ceiling")
    declarations = tuple(d for unit in units.values() for d in unit.declarations)
    by_id = {d.id: d for d in declarations}
    if len(declarations) > MAX_TARGET_RECORDS:
        raise ValueError("complete type population exceeds its record ceiling")
    names, unsafe, work = _source_names(units, declarations, gaps)
    shadowed: dict[str, set[str]] = {p: set() for p in units}
    for source, unit in units.items():
        roots = {n.split(".", 1)[0] for n in names[source]}
        for i, token in enumerate(unit.tokens):
            if i in unit.excluded or token.kind != "identifier" or token.value not in roots:
                continue
            previous = unit.tokens[i - 1] if i else None
            following = unit.tokens[i + 1].value if i + 1 < len(unit.tokens) else None
            if (
                previous is not None
                and previous.kind == "identifier"
                and previous.value not in {"return", "new", "emit", "revert", "is", "using"}
            ) or following in {"=", ";", ",", ")", "]"}:
                shadowed[source].add(token.value)

    def binding(
        source: str, offset: int, spelling: str, *, check_shadow: bool
    ) -> DependencyTypeBinding:
        candidates = tuple(sorted(names[source].get(spelling, ())))
        reason = (
            "UNSUPPORTED_SOURCE_NAMESPACE"
            if source in unsafe
            else "POTENTIAL_LEXICAL_SHADOWING"
            if check_shadow and spelling.split(".", 1)[0] in shadowed[source]
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

    inheritance = tuple(
        DependencyInheritanceBinding(
            inheritor_id=identity, base=binding(source, offset, spelling, check_shadow=False)
        )
        for source, unit in units.items()
        for identity, offset, spelling in unit.bases
    )
    parents: dict[str, set[str]] = {d.id: set() for d in declarations}
    for edge in inheritance:
        if edge.base.target_id is not None:
            parents[edge.inheritor_id].add(edge.base.target_id)
        else:
            gaps.append(
                DependencyTargetGap(
                    source=edge.base.source,
                    byte_start=edge.base.byte_start,
                    reason="INHERITANCE_TARGET_NOT_RESOLVED",
                )
            )
    ancestors: dict[str, set[str]] = {}
    for declaration in declarations:
        visited: set[str] = set()
        pending = list(parents[declaration.id])
        while pending:
            identity = pending.pop()
            work += 1
            if work > MAX_TARGET_WORK:
                raise ValueError("complete inheritance resolution exceeds its work ceiling")
            if identity not in visited:
                visited.add(identity)
                pending.extend(parents[identity] - visited)
        ancestors[declaration.id] = visited
        if declaration.id in visited:
            gaps.append(
                DependencyTargetGap(
                    source=declaration.source,
                    byte_start=declaration.byte_start,
                    reason="INHERITANCE_CYCLE",
                )
            )
    calls: list[DependencyCallBinding] = []
    for source, unit in units.items():
        tokens = unit.tokens
        for i, token in enumerate(tokens):
            if (
                i in unit.excluded
                or token.kind != "punctuation"
                or token.value != "."
                or i + 2 >= len(tokens)
                or tokens[i + 1].kind != "identifier"
                or tokens[i + 2].kind != "punctuation"
                or tokens[i + 2].value not in {"(", "{"}
            ):
                continue
            # A namespace-qualified type conversion is not itself a member dispatch.
            qualified_start, qualified_type = _qualified_before(tokens, i + 2)
            if qualified_type is not None and "." in qualified_type:
                conversion = binding(
                    source, tokens[qualified_start].start, qualified_type, check_shadow=True
                )
                if conversion.target_id is not None:
                    continue
            first, spelling = _qualified_before(tokens, i)
            form: Literal["TYPE_CAST", "TYPE_MEMBER", "UNSUPPORTED_EXPRESSION"] = "TYPE_MEMBER"
            if i and tokens[i - 1].value == ")":
                opening = unit.pairs.get(i - 1)
                if opening is not None and opening + 1 < i - 1:
                    first, spelling = _qualified_before(tokens, opening)
                    form = "TYPE_CAST"
            if spelling is None:
                first, spelling, form = i, "UNSUPPORTED_RECEIVER", "UNSUPPORTED_EXPRESSION"
            receiver = binding(source, tokens[first].start, spelling, check_shadow=True)
            shortfalls = [receiver.shortfall] if receiver.shortfall is not None else []
            if tokens[i + 1].value in _LOW_LEVEL and receiver.target_id is None:
                # The same spelling can name an ABI/library member. Preserve the name
                # failure and record a possibility, not a proved address primitive.
                shortfalls.append("POSSIBLE_LOW_LEVEL_TARGET")
            implementations: tuple[str, ...] = ()
            if receiver.candidate_ids:
                work += len(declarations)
                if work > MAX_TARGET_WORK:
                    raise ValueError("complete implementation lookup exceeds its work ceiling")
                candidates = set(receiver.candidate_ids)
                implementations = tuple(
                    sorted(
                        d.id
                        for d in declarations
                        if d.kind != "interface"
                        and (d.id in candidates or candidates & ancestors[d.id])
                    )
                )
                if any(by_id[i].kind == "interface" for i in candidates) and not implementations:
                    shortfalls.append("NO_SUPPLIED_IMPLEMENTER")
                if gaps:
                    shortfalls.append("IMPLEMENTATION_SET_INCOMPLETE")
            calls.append(
                DependencyCallBinding(
                    source=source,
                    byte_start=tokens[first].start,
                    byte_end=tokens[i + 2].end,
                    member=tokens[i + 1].value,
                    receiver_form=form,
                    receiver=receiver,
                    implementation_ids=implementations,
                    shortfalls=tuple(sorted(set(shortfalls))),
                )
            )
            if len(calls) > MAX_TARGET_RECORDS:
                raise ValueError("complete call-binding population exceeds its record ceiling")
    if any(len(items) > MAX_TARGET_RECORDS for items in (gaps, inheritance)):
        raise ValueError("complete target shortfalls/inheritance exceed their record ceiling")
    gaps = sorted(set(gaps), key=lambda g: (g.source, g.byte_start, g.reason))
    adjacency: dict[str, set[str]] = {p: set() for p in units}
    for imported in imports:
        if imported.target is not None:
            adjacency[imported.source].add(imported.target)
    for edge in inheritance:
        adjacency[edge.base.source].update(by_id[i].source for i in edge.base.candidate_ids)
    for call in calls:
        adjacency[call.source].update(by_id[i].source for i in call.receiver.candidate_ids)
        adjacency[call.source].update(by_id[i].source for i in call.implementation_ids)
    primaries = []
    for primary in units:
        members: set[str] = set()
        pending = [primary]
        while pending:
            member = pending.pop()
            if member not in members:
                members.add(member)
                pending.extend(adjacency[member] - members)
        primaries.append(
            DependencyTargetMembers(
                primary=primary,
                members=tuple(sorted(members)),
                unresolved_call_indices=tuple(
                    i for i, call in enumerate(calls) if call.source in members
                ),
                gap_indices=tuple(i for i, gap in enumerate(gaps) if gap.source in members),
            )
        )
    return DependencyTargetContext(
        source_inventory_sha256=source_inventory_sha256,
        declarations=declarations,
        inheritance=inheritance,
        calls=tuple(calls),
        gaps=tuple(gaps),
        primaries=tuple(primaries),
    )
