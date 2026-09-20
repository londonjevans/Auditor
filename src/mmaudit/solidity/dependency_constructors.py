"""Source-only constructor binding, including implicit bodies and base argument supply.

Constructor declarations are never inherited overloads. A creation binds its exact nominal
type and every supplied contract ancestor, not descendants or deployed initialization order.
"""

from __future__ import annotations

import hashlib

from mmaudit.solidity.dependency_calls import (
    DependencyArgumentExpression,
    DependencyBaseArgumentCall,
    DependencyConstructorBinding,
    DependencyExpressionType,
    DependencyTypedCall,
    _Resolver,
    _Value,
)
from mmaudit.solidity.dependency_scopes import DependencyFunctionDeclaration
from mmaudit.solidity.dependency_targets import MAX_TARGET_RECORDS, _qualified


class _ConstructorResolver(_Resolver):
    def census(self) -> None:
        super().census()
        self.active_calls: set[tuple[str, int]] = set()
        self.active_types: set[str] = set()
        for key, (first, _name_end, _last, _owner) in self.builder.base_arguments.items():
            self.sites[key] = first
        if len(self.sites) > MAX_TARGET_RECORDS:
            raise ValueError("complete constructor call census exceeds its record ceiling")

    def expression(self, source: str, begin: int, end: int, depth: int = 0) -> _Value:
        # The independent grammar anchors creation at the type, excluding the new keyword.
        tokens = self.builder.units[source].tokens
        if begin < end and tokens[begin].value == "new":
            self.bounded(depth)
            return super().expression(source, begin + 1, end, depth + 1)
        return super().expression(source, begin, end, depth)

    def call(self, source: str, opening: int, depth: int = 0) -> DependencyTypedCall:
        self.bounded(depth)
        key = (source, opening)
        if key in self.results:
            return self.results[key]
        unit = self.builder.units[source]
        tokens = unit.tokens
        first = self.sites[key]
        header = self.builder.modifiers.get(key)
        base = self.builder.base_arguments.get(key)
        scope = self.builder.at_scope(source, tokens[opening].start)
        end = header[1] if header is not None else opening
        if header is None and opening > first and tokens[opening - 1].value == "}":
            end = unit.pairs.get(opening - 1, opening)
        spelling = _qualified(tokens[first:end])
        binding = self.builder.binding(source, tokens[first].start, spelling or "UNRESOLVED")
        constructor_header = header is not None and any(
            f.kind == "constructor" and scope is not None and f.scope_id == scope.id
            for f in self.builder.functions
        )
        creation = (
            bool(first)
            and tokens[first - 1].value == "new"
            and not any(t.value == "(" for t in tokens[first:end])
        )
        base_call = base is not None or (
            constructor_header
            and binding.target_id is not None
            and header is not None
            and header[0] != opening
        )
        self.active_calls.add(key)
        try:
            if not creation and not base_call:
                return super().call(source, opening, depth)
            result = self.constructor_call(source, opening, creation=creation, depth=depth + 1)
            self.results[key] = result
            return result
        finally:
            self.active_calls.remove(key)

    def declarations(self, target: str) -> tuple[DependencyFunctionDeclaration, ...]:
        self.builder.charge(len(self.builder.functions))
        return tuple(
            f
            for f in self.builder.functions
            if f.owner_type_id == target and f.kind == "constructor"
        )

    def declaration_gaps(self, declarations: tuple[DependencyFunctionDeclaration, ...]) -> set[str]:
        gaps: set[str] = set()
        if len(declarations) > 1:
            gaps.add("CONSTRUCTOR_DECLARATION_NOT_UNIQUE")
        for function in declarations:
            if function.body_byte_start is None:
                gaps.add("CONSTRUCTOR_BODY_NOT_SUPPLIED")
            if function.visibility != "UNSPECIFIED" or function.returns:
                gaps.add("CONSTRUCTOR_DECLARATION_FORM_UNSUPPORTED")
            tokens = self.builder.units[function.source].tokens
            self.builder.charge(len(tokens))
            header = [
                t.value
                for t in tokens
                if function.byte_start <= t.start < (function.body_byte_start or function.byte_end)
            ]
            if any(word in header for word in {"view", "pure", "virtual", "override", "returns"}):
                gaps.add("CONSTRUCTOR_DECLARATION_FORM_UNSUPPORTED")
        return gaps

    def base_sites(self, owners: set[str]) -> tuple[DependencyBaseArgumentCall, ...]:
        builder = self.builder
        found: dict[tuple[str, int], DependencyBaseArgumentCall] = {}
        candidates = {
            key: (first, name_end, owner)
            for key, (first, name_end, _last, owner) in builder.base_arguments.items()
            if owner in owners
        }
        for key, (first, name_end, _last) in builder.modifiers.items():
            source, opening = key
            scope = builder.at_scope(source, builder.units[source].tokens[opening].start)
            if (
                scope is not None
                and scope.owner_type_id in owners
                and any(
                    f.kind == "constructor" and f.scope_id == scope.id for f in builder.functions
                )
            ):
                candidates[key] = (first, name_end, scope.owner_type_id)
        for (source, opening), (first, end, owner) in candidates.items():
            builder.charge()
            tokens = builder.units[source].tokens
            spelling = _qualified(tokens[first:end])
            binding = builder.binding(source, tokens[first].start, spelling or "UNRESOLVED")
            if binding.target_id is not None:
                found[source, opening] = DependencyBaseArgumentCall(
                    source=source,
                    call_byte_start=tokens[opening].start,
                    owner_type_id=owner,
                    target_id=binding.target_id,
                )
        if len(found) > MAX_TARGET_RECORDS:
            raise ValueError("complete constructor argument supply exceeds its record ceiling")
        return tuple(found[key] for key in sorted(found))

    def construction(
        self, target: str, *, creation: bool, depth: int
    ) -> tuple[DependencyConstructorBinding, set[str]]:
        builder = self.builder
        self.bounded(depth)
        owners = {target} | (builder.ancestors[target] if creation else set())
        required = {i for i in owners if builder.types[i].kind == "contract"}
        required.add(target)
        declarations = {i: self.declarations(i) for i in required}
        gaps = {gap for items in declarations.values() for gap in self.declaration_gaps(items)}
        builder.charge(len(builder.context.inheritance) + len(owners))
        direct_bases = [
            (edge.inheritor_id, edge.base.target_id)
            for edge in builder.context.inheritance
            if edge.inheritor_id in owners and edge.base.target_id is not None
        ]
        if len(direct_bases) != len(set(direct_bases)):
            gaps.add("CONSTRUCTOR_DUPLICATE_DIRECT_BASE")
        if any(builder.types[i].kind == "library" for i in owners):
            gaps.add("INVALID_CONSTRUCTOR_ANCESTOR_KIND")
        if builder.gaps:
            gaps.add("CONSTRUCTOR_NAMESPACE_OR_PARSE_GAPS")
        if target in builder.ancestors[target]:
            gaps.add("CONSTRUCTOR_INHERITANCE_CYCLE")
        if creation and builder.types[target].abstract:
            gaps.add("ABSTRACT_CONTRACT_CREATION")
        if creation:
            # A missing abstract member body cannot be hidden by a non-abstract keyword.
            for function in builder.functions:
                builder.charge()
                if (
                    function.owner_type_id in owners
                    and function.kind == "function"
                    and function.body_byte_start is None
                ):
                    members = [
                        f
                        for f in builder.members(target, function.name, len(function.parameters))
                        if builder.signature(f) == builder.signature(function)
                    ]
                    if len(members) != 1 or members[0].body_byte_start is None:
                        gaps.add("CONSTRUCTED_TYPE_ABSTRACTNESS_NOT_ESTABLISHED")
        sites: list[DependencyBaseArgumentCall] = []
        if creation and target in self.active_types:
            gaps.add("RECURSIVE_CONSTRUCTOR_DEPENDENCY")
        elif creation:
            self.active_types.add(target)
            try:
                for site in self.base_sites(required):
                    if site.target_id not in required or site.target_id == target:
                        gaps.add("BASE_CONSTRUCTOR_TARGET_OUTSIDE_ANCESTRY")
                        continue
                    tokens = builder.units[site.source].tokens
                    opening = next(
                        i for i, t in enumerate(tokens) if t.start == site.call_byte_start
                    )
                    key = (site.source, opening)
                    if key in self.active_calls:
                        gaps.add("RECURSIVE_CONSTRUCTOR_DEPENDENCY")
                        continue
                    child = self.call(site.source, opening, depth + 1)
                    if child.dispatch != "BASE_CONSTRUCTOR" or child.constructor_binding is None:
                        gaps.add("BASE_ARGUMENT_CALL_NOT_RESOLVED")
                        continue
                    sites.append(site)
                    if child.shortfalls:
                        gaps.add("BASE_ARGUMENT_CALL_NOT_RESOLVED")
                for owner, items in declarations.items():
                    if owner == target:
                        continue
                    supplied = [s for s in sites if s.target_id == owner]
                    if len(supplied) > 1:
                        gaps.add("DUPLICATE_BASE_CONSTRUCTOR_ARGUMENTS")
                    if not supplied and any(f.parameters for f in items):
                        gaps.add("MISSING_BASE_CONSTRUCTOR_ARGUMENTS")
            finally:
                self.active_types.remove(target)
        return DependencyConstructorBinding(
            target_id=target,
            required_type_ids=tuple(sorted(required)),
            constructor_member_ids=tuple(
                sorted(f.id for items in declarations.values() for f in items)
            ),
            implicit_type_ids=tuple(sorted(i for i, items in declarations.items() if not items)),
            base_argument_calls=tuple(sorted(sites, key=lambda s: (s.source, s.call_byte_start))),
        ), gaps

    def constructor_call(
        self, source: str, opening: int, *, creation: bool, depth: int
    ) -> DependencyTypedCall:
        self.bounded(depth)
        builder = self.builder
        unit = builder.units[source]
        tokens = unit.tokens
        first = self.sites[source, opening]
        closing = unit.pairs.get(opening, opening)
        end = opening
        gaps: set[str] = set()
        if tokens[opening - 1].value == "}":
            end = unit.pairs.get(opening - 1, opening)
            gaps.add("CONSTRUCTOR_CALL_OPTIONS_UNRESOLVED")
        spelling = _qualified(tokens[first:end])
        binding = builder.binding(source, tokens[first].start, spelling or "UNRESOLVED")
        scope = builder.at_scope(source, tokens[opening].start)
        if scope is None or builder.unsafe(scope):
            gaps.add("LEXICAL_SCOPE_NOT_ESTABLISHED")
        if spelling is None:
            gaps.add("CONSTRUCTOR_TYPE_FORM_UNSUPPORTED")
        if spelling and builder.shadowed(scope, tokens[first].start, spelling.split(".")[0]):
            gaps.add("CONSTRUCTOR_TYPE_NAME_SHADOWED")
        ranges = builder.segments(source, opening + 1, closing, ",")
        if len(ranges) > 64:
            raise ValueError("complete constructor argument population exceeds its ceiling")
        arguments: list[DependencyArgumentExpression] = []
        for begin, last in ranges:
            if begin == last:
                gaps.add("EMPTY_ARGUMENT_EXPRESSION")
            else:
                argument = self.argument(source, begin, last, depth + 1)
                arguments.append(argument)
                gaps.update(argument.shortfalls)
        if closing == opening:
            gaps.add("CONSTRUCTOR_ARGUMENTS_NOT_PARSED")
        target = binding.target_id
        constructor = None
        candidates: tuple[DependencyFunctionDeclaration, ...] = ()
        members: tuple[DependencyFunctionDeclaration, ...] = ()
        result_types: tuple[DependencyExpressionType, ...] = ()
        if target is None:
            gaps.add(binding.shortfall or "CONSTRUCTOR_TYPE_NOT_RESOLVED")
        elif builder.types[target].kind != "contract":
            gaps.add("CONSTRUCTOR_TARGET_NOT_CONTRACT")
        else:
            if not creation and (
                scope is None or target not in builder.ancestors[scope.owner_type_id]
            ):
                gaps.add("BASE_CONSTRUCTOR_TARGET_OUTSIDE_ANCESTRY")
            candidates = self.declarations(target)
            gaps.update(self.declaration_gaps(candidates))
            if not candidates:
                if arguments:
                    gaps.add("IMPLICIT_CONSTRUCTOR_ARGUMENTS_NOT_EMPTY")
            elif len(candidates) == 1:
                function = candidates[0]
                if len(arguments) != len(function.parameters):
                    gaps.add("CONSTRUCTOR_ARGUMENT_COUNT_MISMATCH")
                else:
                    conversions = [
                        self.accepts(a.expression_type, self.type(p))
                        for a, p in zip(arguments, function.parameters, strict=True)
                    ]
                    if False in conversions:
                        gaps.add("CONSTRUCTOR_ARGUMENT_TYPE_MISMATCH")
                    elif None in conversions:
                        gaps.add("CONSTRUCTOR_ARGUMENT_CONVERSION_UNRESOLVED")
                    else:
                        members = candidates
            if not creation:
                for argument in arguments:
                    for identity in argument.value_ids:
                        value = next(v for v in builder.values if v.id == identity)
                        if value.kind != "PARAMETER" or scope is None or value.scope_id != scope.id:
                            gaps.add("BASE_ARGUMENT_VALUE_SCOPE_UNSUPPORTED")
                    for offset in argument.nested_call_offsets:
                        child = next(
                            (
                                c
                                for c in self.results.values()
                                if c.source == source and c.call_byte_start == offset
                            ),
                            None,
                        )
                        if child is None or child.dispatch not in {"CONVERSION", "INTRINSIC"}:
                            gaps.add("BASE_ARGUMENT_FUNCTION_CALL_UNRESOLVED")
            constructor, missing = self.construction(target, creation=creation, depth=depth + 1)
            gaps.update(missing)
            if creation:
                result_types = (
                    DependencyExpressionType(
                        kind="NOMINAL", spelling=binding.spelling, target_id=target
                    ),
                )
        return DependencyTypedCall(
            source=source,
            source_sha256=hashlib.sha256(self.sources[source]).hexdigest(),
            byte_start=tokens[first].start,
            byte_end=tokens[closing].end,
            call_byte_start=tokens[opening].start,
            scope_id=scope.id if scope else None,
            callee=spelling or "UNRESOLVED",
            dispatch="CREATION" if creation else "BASE_CONSTRUCTOR",
            receiver=None,
            arguments=tuple(arguments),
            result_types=result_types,
            candidate_member_ids=tuple(sorted(f.id for f in candidates)),
            member_ids=tuple(sorted(f.id for f in members)),
            implementation_ids=constructor.required_type_ids if constructor else (),
            implementation_member_ids=constructor.constructor_member_ids if constructor else (),
            constructor_binding=constructor,
            shortfalls=tuple(sorted(gaps)),
            resolution="NOT_ESTABLISHED" if gaps else "STATIC_DECLARATIONS_BOUND",
        )
