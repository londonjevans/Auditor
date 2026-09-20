"""Source-recomputed closure composition; raw heuristic graph facts are never regraded.

The independent source grammar and typed resolver supply the complete supported call
population. Original graph facts must also join that population and meet their own
provenance/confidence gate. This proves a bounded in-tree source dependency relation,
not compilation, deployment wiring, reachability, independent provenance or audit quality.
"""

from __future__ import annotations

import hashlib
from bisect import bisect_right
from itertools import accumulate
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import SolidityEntityKind, SolidityGraphKind, SolidityProvenance
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.repository.chunking import line_range_hash
from mmaudit.solidity.dependency_scopes import (
    _BUILTIN,
    DependencyFunctionDeclaration,
    DependencyValueDeclaration,
)
from mmaudit.solidity.dependency_targets import (
    MAX_TARGET_RECORDS,
    DependencyTargetGap,
    DependencyTypeDeclaration,
    _Record,
)

if TYPE_CHECKING:
    from mmaudit.solidity.dependency_closure import DevelopmentDependencyClosure
    from mmaudit.solidity.index import SolidityIndexBuild

MAX_STATIC_CLOSURE_WORK = 1_000_000
MAX_STATIC_CLOSURE_BYTES = 393_216
STATIC_CLOSURE_KINDS = tuple(
    sorted(
        {
            SolidityGraphKind.DEPENDENCY,
            SolidityGraphKind.INHERITANCE,
            SolidityGraphKind.MODIFIER,
            SolidityGraphKind.INTERNAL_CALL,
            SolidityGraphKind.EXTERNAL_CALL,
            SolidityGraphKind.LOW_LEVEL_CALL,
            SolidityGraphKind.DELEGATECALL,
            SolidityGraphKind.CONTRACT_CREATION,
        },
        key=lambda kind: kind.value,
    )
)
_SHA = r"^[0-9a-f]{64}$"
_PATH = r"^(?:[A-Za-z0-9][A-Za-z0-9._-]*/)*[A-Za-z0-9][A-Za-z0-9._-]*\.sol$"
type StaticClosureStatus = Literal["NOT_ESTABLISHED", "CALL_CLOSED"]
type _Declaration = (
    DependencyTypeDeclaration | DependencyFunctionDeclaration | DependencyValueDeclaration
)
type _EdgeBasis = Literal["IMPORT", "INHERITANCE", "TYPED_CALL", "DECLARED_TYPE"]
type _Population = Literal[
    "IMPORT",
    "REMAP",
    "PARSE",
    "TARGET",
    "SCOPE",
    "CALL",
    "SYNTAX",
    "GRAPH",
    "EDGE_OMISSION",
    "FACT_OMISSION",
    "GRAPH_WARNING",
    "DECLARED_TYPE",
    "CONTEXT",
]


class DependencyStaticEdge(_Record):
    """One exact source-to-source dependency; its referenced declaration is retained too."""

    kind: SolidityGraphKind
    source: str = Field(pattern=_PATH, max_length=512)
    target: str = Field(pattern=_PATH, max_length=512)
    basis: _EdgeBasis
    evidence_index: int = Field(ge=0, lt=MAX_TARGET_RECORDS)
    target_declaration_id: str | None = Field(default=None, pattern=_SHA)


class DependencyGraphSymbolBinding(_Record):
    graph_symbol_id: str = Field(min_length=1, max_length=512)
    declaration_ids: tuple[str, ...] = Field(max_length=MAX_TARGET_RECORDS)

    @field_validator("declaration_ids")
    @classmethod
    def exact_candidates(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("graph symbol candidates must be sorted and unique")
        return value


class DependencyStaticCallLines(_Record):
    call_index: int = Field(ge=0, lt=MAX_TARGET_RECORDS)
    line_start: int = Field(ge=1, le=10_000)
    line_end: int = Field(ge=1, le=10_000)

    @model_validator(mode="after")
    def ordered_lines(self) -> Self:
        if self.line_end < self.line_start:
            raise ValueError("static call line range is reversed")
        return self


class DependencyGraphFactJoin(_Record):
    graph_fact_index: int = Field(ge=0, lt=MAX_TARGET_RECORDS)
    call_indices: tuple[int, ...] = Field(max_length=MAX_TARGET_RECORDS)
    inheritance_indices: tuple[int, ...] = Field(max_length=MAX_TARGET_RECORDS)
    shortfalls: tuple[str, ...] = Field(max_length=32)


class DependencyStaticShortfall(_Record):
    source: str | None = Field(default=None, pattern=_PATH, max_length=512)
    global_scope: bool
    population: _Population
    evidence_index: int = Field(ge=0, lt=MAX_TARGET_RECORDS)
    reason: str = Field(pattern=r"^[A-Z_]+$", max_length=128)


class DependencyStaticPrimary(_Record):
    primary: str = Field(pattern=_PATH, max_length=512)
    members: tuple[str, ...] = Field(min_length=1, max_length=256)
    edge_indices: tuple[int, ...] = Field(max_length=MAX_TARGET_RECORDS)
    shortfall_indices: tuple[int, ...] = Field(max_length=MAX_TARGET_RECORDS)
    call_closure: StaticClosureStatus


class DevelopmentStaticCallClosure(_Record):
    policy: Literal["SOURCE_GRAPH_SYNTAX_TYPED_CALL_CLOSURE_V1"] = (
        "SOURCE_GRAPH_SYNTAX_TYPED_CALL_CLOSURE_V1"
    )
    scope: Literal["SUPPORTED_STATIC_SUPPLIED_TREE_NOT_DEPLOYMENT_OR_REACHABILITY"] = (
        "SUPPORTED_STATIC_SUPPLIED_TREE_NOT_DEPLOYMENT_OR_REACHABILITY"
    )
    minimum_original_graph_confidence: float = Field(default=0.9, ge=0.9, le=0.9)
    required_graph_kinds: tuple[SolidityGraphKind, ...] = STATIC_CLOSURE_KINDS
    source_inventory_sha256: str = Field(pattern=_SHA)
    original_graph_sha256: str = Field(pattern=_SHA)
    original_graph_facts_sha256: str = Field(pattern=_SHA)
    closure_inputs_sha256: str = Field(pattern=_SHA)
    graph_symbols: tuple[DependencyGraphSymbolBinding, ...] = Field(max_length=8192)
    call_lines: tuple[DependencyStaticCallLines, ...] = Field(max_length=MAX_TARGET_RECORDS)
    graph_joins: tuple[DependencyGraphFactJoin, ...] = Field(max_length=MAX_TARGET_RECORDS)
    edges: tuple[DependencyStaticEdge, ...] = Field(max_length=MAX_TARGET_RECORDS)
    edges_sha256: str = Field(pattern=_SHA)
    shortfalls: tuple[DependencyStaticShortfall, ...] = Field(max_length=MAX_TARGET_RECORDS)
    primaries: tuple[DependencyStaticPrimary, ...] = Field(min_length=1, max_length=256)
    call_closure: StaticClosureStatus
    runtime_authority: Literal[False] = False
    audit_complete: Literal[False] = False
    qualification_eligible: Literal[False] = False
    proof_sha256: str = Field(pattern=_SHA)

    @field_validator("runtime_authority", "audit_complete", "qualification_eligible", mode="before")
    @classmethod
    def no_authority(cls, value: object) -> Literal[False]:
        if value is not False:
            raise ValueError("static source closure cannot grant audit or runtime authority")
        return False

    @model_validator(mode="after")
    def exact_proof(self) -> Self:
        paths = tuple(p.primary for p in self.primaries)
        if paths != tuple(sorted(set(paths))) or self.required_graph_kinds != STATIC_CLOSURE_KINDS:
            raise ValueError("static closure changes its complete source or edge universe")
        symbols = tuple(s.graph_symbol_id for s in self.graph_symbols)
        if symbols != tuple(sorted(set(symbols))):
            raise ValueError("static closure graph symbol population differs")
        if tuple(c.call_index for c in self.call_lines) != tuple(range(len(self.call_lines))):
            raise ValueError("static closure line census must retain every call index")
        if tuple(j.graph_fact_index for j in self.graph_joins) != tuple(
            range(len(self.graph_joins))
        ):
            raise ValueError("static closure joins must retain every original graph fact")
        if any(e.source not in paths or e.target not in paths for e in self.edges):
            raise ValueError("static closure edge leaves its source universe")
        for p in self.primaries:
            if (
                p.members != tuple(sorted(set(p.members)))
                or p.primary not in p.members
                or (not set(p.members) <= set(paths))
            ):
                raise ValueError("static closure primary members differ")
            expected_gaps = tuple(
                i for i, g in enumerate(self.shortfalls) if g.global_scope or g.source in p.members
            )
            if p.shortfall_indices != expected_gaps or p.edge_indices != tuple(
                i for i, e in enumerate(self.edges) if e.source in p.members
            ):
                raise ValueError("static closure primary evidence population differs")
            if (p.call_closure == "CALL_CLOSED") != (not expected_gaps):
                raise ValueError("static closure primary status contradicts its shortfalls")
        if (self.call_closure == "CALL_CLOSED") != all(
            p.call_closure == "CALL_CLOSED" for p in self.primaries
        ):
            raise ValueError("static closure aggregate omits a primary shortfall")
        if self.edges_sha256 != canonical_sha256([e.model_dump(mode="json") for e in self.edges]):
            raise ValueError("static closure edge digest differs")
        if self.proof_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"proof_sha256"})
        ):
            raise ValueError("static closure proof digest differs")
        if len(self.model_dump_json().encode()) > MAX_STATIC_CLOSURE_BYTES:
            raise ValueError("complete static closure proof exceeds its byte ceiling")
        return self

    def validate_inputs(self, witness: DevelopmentDependencyClosure) -> None:
        """Self-hashes are insufficient; rederive every disposition and transitive member set."""
        if self != _compose(witness, self.graph_symbols, self.call_lines):
            raise ValueError("static closure differs from its exact source-evidence composition")


class _Work:
    def __init__(self) -> None:
        self.used = 0

    def charge(self, count: int = 1) -> None:
        self.used += count
        if self.used > MAX_STATIC_CLOSURE_WORK:
            raise ValueError("complete static closure computation exceeds its work ceiling")


def _inputs(w: DevelopmentDependencyClosure) -> dict[str, Any]:
    fields = w.model_dump(
        mode="json",
        exclude={
            "schema_version",
            "dependency_closure",
            "static_call_closure",
            "witness_sha256",
            "primaries",
        },
    )
    fields["import_primaries"] = [
        {
            "primary": p.primary,
            "import_members": p.import_members,
            "import_closure": p.import_closure,
        }
        for p in w.primaries
    ]
    return fields


def _compose(
    w: DevelopmentDependencyClosure,
    graph_symbols: tuple[DependencyGraphSymbolBinding, ...],
    call_lines: tuple[DependencyStaticCallLines, ...],
) -> DevelopmentStaticCallClosure:
    target, scoped, calls, syntax = (
        w.target_context,
        w.scoped_context,
        w.call_context,
        w.syntax_context,
    )
    if (
        target is None
        or scoped is None
        or calls is None
        or syntax is None
        or (calls.policy != "SOURCE_CALL_MODIFIER_AND_CONSTRUCTOR_RESOLUTION_V3")
    ):
        raise ValueError(
            "static closure requires complete versioned constructor/call/syntax inputs"
        )
    syntax.validate_call_context(calls)
    work = _Work()
    paths = tuple(s.filename for s in w.source_inventory)
    types = {d.id: d for d in target.declarations}
    functions = {f.id: f for f in scoped.functions}
    values = {v.id: v for v in scoped.values}
    declarations: dict[str, _Declaration] = {**types, **functions, **values}
    required_symbols = {v for f in w.graph_facts for v in (f.source_id, f.target_id)}
    if tuple(s.graph_symbol_id for s in graph_symbols) != tuple(sorted(required_symbols)) or any(
        not set(s.declaration_ids) <= set(declarations) for s in graph_symbols
    ):
        raise ValueError("static closure graph bindings differ from original symbols/declarations")
    if tuple(c.call_index for c in call_lines) != tuple(range(len(calls.calls))):
        raise ValueError("static closure line census differs from the complete typed population")
    edges: list[DependencyStaticEdge] = []
    gaps: list[DependencyStaticShortfall] = []

    def gap(
        population: _Population,
        index: int,
        reason: str,
        source: str | None,
        *,
        global_: bool = False,
    ) -> None:
        work.charge()
        gaps.append(
            DependencyStaticShortfall(
                source=source,
                global_scope=global_,
                population=population,
                evidence_index=index,
                reason=reason,
            )
        )
        if len(gaps) > MAX_TARGET_RECORDS:
            raise ValueError("complete static closure shortfalls exceed their record ceiling")

    def edge(
        kind: SolidityGraphKind,
        source: str,
        dest: str,
        basis: _EdgeBasis,
        index: int,
        identity: str | None = None,
    ) -> None:
        work.charge()
        edges.append(
            DependencyStaticEdge(
                kind=kind,
                source=source,
                target=dest,
                basis=basis,
                evidence_index=index,
                target_declaration_id=identity,
            )
        )
        if len(edges) > MAX_TARGET_RECORDS:
            raise ValueError("complete static closure edges exceed their record ceiling")

    for i, item in enumerate(w.imports):
        if item.target is None:
            gap("IMPORT", i, item.shortfall or "UNRESOLVED_IMPORT", item.source, global_=True)
        else:
            edge(SolidityGraphKind.DEPENDENCY, item.source, item.target, "IMPORT", i)
    for i, _ in enumerate(w.unsupported_remapping_lines):
        gap("REMAP", i, "UNSUPPORTED_REMAPPING", None, global_=True)
    for i, parse_gap in enumerate(w.parse_gaps):
        gap("PARSE", i, parse_gap.reason, parse_gap.source, global_=True)
    gap_populations: tuple[tuple[_Population, tuple[DependencyTargetGap, ...]], ...] = (
        ("TARGET", target.gaps),
        ("SCOPE", scoped.gaps),
        ("CALL", calls.gaps),
    )
    for population, gap_records in gap_populations:
        for i, context_gap in enumerate(gap_records):
            gap(population, i, context_gap.reason, context_gap.source, global_=True)
    for i, syntax_gap in enumerate(syntax.gaps):
        gap("SYNTAX", i, syntax_gap.reason, syntax_gap.source, global_=True)
    for i, syntax_call in enumerate(syntax.calls):
        if syntax_call.typed_match != "EXACT_SPAN":
            gap("SYNTAX", i, syntax_call.typed_match, syntax_call.source, global_=True)
    for i in syntax.unmatched_typed_call_indices:
        gap("CALL", i, "TYPED_CALL_MISSING_FROM_SOURCE_CENSUS", calls.calls[i].source, global_=True)
    omitted_populations: tuple[tuple[_Population, int, str], ...] = (
        ("EDGE_OMISSION", len(w.graph_edge_omissions), "ORIGINAL_GRAPH_EDGE_OMISSION"),
        ("FACT_OMISSION", len(w.graph_fact_omissions), "ORIGINAL_GRAPH_FACT_OMISSION"),
        ("GRAPH_WARNING", len(w.graph_warnings), "ORIGINAL_GRAPH_WARNING"),
    )
    for population, count, reason in omitted_populations:
        for i in range(count):
            gap(population, i, reason, None, global_=True)
    if not w.graph_generation_complete and not (w.graph_edge_omissions or w.graph_fact_omissions):
        gap("GRAPH", 0, "ORIGINAL_GRAPH_GENERATION_INCOMPLETE", None, global_=True)
    for i, relation in enumerate(target.inheritance):
        if relation.base.target_id is None:
            gap("TARGET", i, "INHERITANCE_TARGET_UNRESOLVED", relation.base.source, global_=True)
        else:
            edge(
                SolidityGraphKind.INHERITANCE,
                types[relation.inheritor_id].source,
                types[relation.base.target_id].source,
                "INHERITANCE",
                i,
                relation.base.target_id,
            )
    bindings = [v.value_type for v in scoped.values] + [
        b for f in scoped.functions for b in (*f.parameters, *f.returns)
    ]
    if len(bindings) > MAX_TARGET_RECORDS:
        raise ValueError("complete declared-type population exceeds its record ceiling")
    for i, binding in enumerate(bindings):
        if binding.target_id is not None:
            edge(
                SolidityGraphKind.DEPENDENCY,
                binding.source,
                types[binding.target_id].source,
                "DECLARED_TYPE",
                i,
                binding.target_id,
            )
        elif not _BUILTIN.fullmatch(binding.spelling):
            gap("DECLARED_TYPE", i, "DECLARED_TYPE_NOT_RESOLVED", binding.source, global_=True)

    call_kinds: list[SolidityGraphKind] = []
    call_owners: list[set[str]] = []
    for i, call in enumerate(calls.calls):
        work.charge(len(functions) + len(values))
        call_owners.append(
            {
                f.id
                for f in (*scoped.functions, *scoped.values)
                if f.source == call.source
                and f.byte_start <= call.byte_start < call.byte_end <= f.byte_end
            }
        )
        kind = {
            "MEMBER": SolidityGraphKind.EXTERNAL_CALL,
            "INTERNAL": SolidityGraphKind.INTERNAL_CALL,
            "MODIFIER": SolidityGraphKind.MODIFIER,
            "IMPLICIT_MODIFIER": SolidityGraphKind.MODIFIER,
            "CREATION": SolidityGraphKind.CONTRACT_CREATION,
            "BASE_CONSTRUCTOR": SolidityGraphKind.INHERITANCE,
        }.get(call.dispatch, SolidityGraphKind.DEPENDENCY)
        if call.dispatch == "LIBRARY":
            kind = (
                SolidityGraphKind.DELEGATECALL
                if any(functions[m].visibility in {"external", "public"} for m in call.member_ids)
                else SolidityGraphKind.INTERNAL_CALL
            )
        call_kinds.append(kind)
        if call.resolution != "STATIC_DECLARATIONS_BOUND":
            for reason in call.shortfalls or ("TYPED_CALL_NOT_RESOLVED",):
                gap("CALL", i, reason, call.source)
        identities = set(
            (
                *call.candidate_member_ids,
                *call.member_ids,
                *call.implementation_ids,
                *call.implementation_member_ids,
            )
        )
        for expression in (
            *call.result_types,
            *(a.expression_type for a in call.arguments),
            *((call.receiver.expression_type,) if call.receiver else ()),
        ):
            if expression.target_id is not None:
                identities.add(expression.target_id)
        for identity in sorted(identities):
            edge(kind, call.source, declarations[identity].source, "TYPED_CALL", i, identity)

    symbols = {s.graph_symbol_id: s.declaration_ids for s in graph_symbols}
    joins: list[DependencyGraphFactJoin] = []
    for i, fact in enumerate(w.graph_facts):
        reasons = set()
        source_ids, target_ids = symbols[fact.source_id], symbols[fact.target_id]
        if len(source_ids) != 1 or len(target_ids) != 1:
            reasons.add("ORIGINAL_GRAPH_SYMBOL_NOT_UNIQUE")
        matched_calls, matched_inheritance = [], []
        if len(source_ids) == len(target_ids) == 1:
            origin, dest = source_ids[0], target_ids[0]
            if declarations[origin].source != fact.source:
                reasons.add("ORIGINAL_GRAPH_SOURCE_MISMATCH")
            work.charge(len(calls.calls) + len(target.inheritance))
            for j, call in enumerate(calls.calls):
                member_ids = (
                    *call.member_ids,
                    *call.implementation_ids,
                    *call.implementation_member_ids,
                )
                lines = call_lines[j]
                if (
                    origin in call_owners[j]
                    and dest in member_ids
                    and fact.kind == call_kinds[j]
                    and (
                        call.source == fact.source
                        and fact.line_start <= lines.line_start <= lines.line_end <= fact.line_end
                    )
                ):
                    matched_calls.append(j)
            if fact.kind == SolidityGraphKind.INHERITANCE:
                matched_inheritance = [
                    j
                    for j, rel in enumerate(target.inheritance)
                    if rel.inheritor_id == origin and rel.base.target_id == dest
                ]
        if not matched_calls and not matched_inheritance:
            reasons.add("ORIGINAL_GRAPH_FACT_NOT_SOURCE_JOINED")
        if fact.confidence < 0.9:
            reasons.add("ORIGINAL_GRAPH_CONFIDENCE_BELOW_POLICY")
        if fact.provenance not in {SolidityProvenance.COMPILER, SolidityProvenance.STATIC_TOOL}:
            reasons.add("ORIGINAL_GRAPH_PROVENANCE_INADEQUATE")
        for reason in sorted(reasons):
            gap("GRAPH", i, reason, fact.source)
        joins.append(
            DependencyGraphFactJoin(
                graph_fact_index=i,
                call_indices=tuple(matched_calls),
                inheritance_indices=tuple(matched_inheritance),
                shortfalls=tuple(sorted(reasons)),
            )
        )

    ordered_edges = tuple(
        sorted(
            set(edges),
            key=lambda e: (
                e.source,
                e.target,
                e.kind.value,
                e.basis,
                e.evidence_index,
                e.target_declaration_id or "",
            ),
        )
    )
    adjacency = {p: {p} for p in paths}
    for e in ordered_edges:
        adjacency[e.source].add(e.target)
    memberships = {}
    for primary in paths:
        visited: set[str] = set()
        pending = [primary]
        while pending:
            work.charge()
            member = pending.pop()
            if member not in visited:
                visited.add(member)
                pending.extend(adjacency[member] - visited)
        memberships[primary] = visited
    for i, prior in enumerate(calls.primaries):
        if not set(prior.members) <= memberships[prior.primary]:
            gap("CONTEXT", i, "COMPONENT_CONTEXT_MEMBERS_NOT_RETAINED", prior.primary)
    primaries = []
    for primary in paths:
        members = memberships[primary]
        work.charge(len(gaps) + len(ordered_edges))
        shortfalls = tuple(i for i, g in enumerate(gaps) if g.global_scope or g.source in members)
        primaries.append(
            DependencyStaticPrimary(
                primary=primary,
                members=tuple(sorted(members)),
                edge_indices=tuple(i for i, e in enumerate(ordered_edges) if e.source in members),
                shortfall_indices=shortfalls,
                call_closure="NOT_ESTABLISHED" if shortfalls else "CALL_CLOSED",
            )
        )
    fields: dict[str, Any] = dict(
        source_inventory_sha256=w.source_inventory_sha256,
        original_graph_sha256=w.graph_sha256,
        original_graph_facts_sha256=canonical_sha256(
            [f.model_dump(mode="json") for f in w.graph_facts]
        ),
        closure_inputs_sha256=canonical_sha256(_inputs(w)),
        graph_symbols=graph_symbols,
        call_lines=call_lines,
        graph_joins=tuple(joins),
        edges=ordered_edges,
        edges_sha256=canonical_sha256([e.model_dump(mode="json") for e in ordered_edges]),
        shortfalls=tuple(gaps),
        primaries=tuple(primaries),
        call_closure="CALL_CLOSED"
        if all(p.call_closure == "CALL_CLOSED" for p in primaries)
        else "NOT_ESTABLISHED",
    )
    provisional = DevelopmentStaticCallClosure.model_construct(**fields, proof_sha256="0" * 64)
    fields["proof_sha256"] = canonical_sha256(
        provisional.model_dump(mode="json", exclude={"proof_sha256"})
    )
    return DevelopmentStaticCallClosure.model_validate(fields)


def compute_static_call_closure(
    *,
    witness: DevelopmentDependencyClosure,
    source_files: tuple[tuple[str, bytes], ...],
    source_index: SolidityIndexBuild,
) -> DevelopmentStaticCallClosure:
    """Bind graph symbols and line ranges from actual source/index data, then compose closure."""
    target, scoped, calls = witness.target_context, witness.scoped_context, witness.call_context
    if target is None or scoped is None or calls is None:
        raise ValueError("static closure requires all source declaration and call contexts")
    work = _Work()
    raw_sources = dict(source_files)
    if tuple(
        (name, hashlib.sha256(raw).hexdigest(), len(raw)) for name, raw in source_files
    ) != tuple((s.filename, s.sha256, s.size) for s in witness.source_inventory):
        raise ValueError("static closure source bytes differ from their witnessed inventory")
    line_starts = {
        p: [
            0,
            *accumulate(
                len(line.encode("utf-8")) for line in raw.decode("utf-8").splitlines(keepends=True)
            ),
        ]
        for p, raw in source_files
    }
    call_lines = tuple(
        DependencyStaticCallLines(
            call_index=i,
            line_start=bisect_right(line_starts[c.source], c.byte_start),
            line_end=bisect_right(line_starts[c.source], c.byte_end - 1),
        )
        for i, c in enumerate(calls.calls)
    )
    types = {d.id: d for d in target.declarations}
    wanted = sorted({v for f in witness.graph_facts for v in (f.source_id, f.target_id)})
    symbols = []
    for identity in wanted:
        work.charge(len(source_index.index.entities))
        entities = [e for e in source_index.index.entities if e.id == identity]
        candidates: set[str] = set()
        if len(entities) == 1:
            entity = entities[0]
            work.charge(len(types) + len(scoped.functions) + len(scoped.values))
            entity_raw = raw_sources.get(entity.path)
            # Charge byte-dependent hashing work as well as metadata comparisons.
            work.charge(0 if entity_raw is None else (len(entity_raw) + 63) // 64)
            # The existing index hashes an inclusive line range, not the entire file.
            # Full-file identity was checked against the witnessed inventory above.
            source_matches = (
                entity_raw is not None
                and entity.byte_end <= len(entity_raw)
                and (
                    entity.source_hash
                    == line_range_hash(
                        entity_raw.decode("utf-8", errors="strict"),
                        entity.start_line,
                        entity.end_line,
                    )
                )
            )
            records: list[_Declaration] = [
                d for d in target.declarations if d.kind == entity.kind.value
            ]
            if entity.kind in {
                SolidityEntityKind.STATE_VARIABLE,
                SolidityEntityKind.IMMUTABLE,
                SolidityEntityKind.CONSTANT,
            }:
                records.extend(v for v in scoped.values if v.kind == "STATE")
            if entity.kind in {
                SolidityEntityKind.FUNCTION,
                SolidityEntityKind.CONSTRUCTOR,
                SolidityEntityKind.MODIFIER,
            }:
                records.extend(f for f in scoped.functions if f.kind == entity.kind.value)
            for d in records:
                if d.source != entity.path or d.name != entity.name or d.source not in raw_sources:
                    continue
                if not source_matches:
                    continue
                if not isinstance(d, DependencyTypeDeclaration) and (
                    types[d.owner_type_id].name != entity.contract_name
                ):
                    continue
                if entity.byte_start <= d.byte_start < d.byte_end <= entity.byte_end:
                    candidates.add(d.id)
        symbols.append(
            DependencyGraphSymbolBinding(
                graph_symbol_id=identity, declaration_ids=tuple(sorted(candidates))
            )
        )
    return _compose(witness, tuple(symbols), call_lines)
