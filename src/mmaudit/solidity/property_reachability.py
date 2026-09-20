"""Compiler-reference scheduling evidence; not path feasibility or property truth."""

from __future__ import annotations

import hashlib
import json
from bisect import bisect_right
from collections import defaultdict
from itertools import pairwise
from pathlib import PurePosixPath
from typing import Any, Literal, Self

from pydantic import ConfigDict, Field, model_validator

from mmaudit.benchmark.mutation_discovery import _nodes
from mmaudit.models.schemas import PropertyCorpus, StrictModel
from mmaudit.repository.chunking import line_range_hash
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.scanners.foundry_inventory import (
    FoundryInventorySourceBinding,
    compiler_catalog_source_bindings,
)
from mmaudit.scanners.foundry_inventory_runner import (
    FoundryInventoryRunResult,
    validated_foundry_compiler_input,
)

_SHA = r"^[0-9a-f]{64}$"


def _hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class PropertyReachabilityLimits(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    maximum_graph_items: int = Field(default=200_000, ge=1, le=200_000)
    maximum_property_relations: int = Field(default=100_000, ge=1, le=100_000)
    maximum_seed_checks: int = Field(default=1_000_000, ge=1, le=1_000_000)


class _Identified(StrictModel):
    id: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def exact_identity(self) -> Self:
        if self.id != _hash(self.model_dump(mode="json", exclude={"id"})):
            raise ValueError("compiler reference identity differs from its full contents")
        return self


class CompilerPropertyRegion(_Identified):
    build_info_sha256: str = Field(pattern=_SHA)
    ast_node_id: int = Field(ge=0)
    source_id: int = Field(ge=0)
    path: str = Field(min_length=1, max_length=4_096)
    start_byte: int = Field(ge=0)
    end_byte_exclusive: int = Field(gt=0)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    kind: Literal["FunctionDefinition", "ModifierDefinition"]
    virtual: bool


class CompilerPropertyReference(_Identified):
    caller_id: str = Field(pattern=_SHA)
    target_id: str = Field(pattern=_SHA)
    ast_node_id: int = Field(ge=0)
    start_byte: int = Field(ge=0)
    end_byte_exclusive: int = Field(gt=0)
    kind: Literal["DIRECT_INTERNAL_CALL", "MODIFIER_INVOCATION"]


class UnresolvedCompilerPropertyReference(_Identified):
    caller_id: str = Field(pattern=_SHA)
    ast_node_id: int = Field(ge=0)
    start_byte: int = Field(ge=0)
    end_byte_exclusive: int = Field(gt=0)
    reason: Literal[
        "UNRESOLVED_OR_DYNAMIC_CALL", "UNRESOLVED_OR_VIRTUAL_MODIFIER", "INLINE_ASSEMBLY"
    ]


class CompilerPropertyReachabilityRow(StrictModel):
    property_id: str = Field(pattern=r"^prop-[0-9a-f]{24}$")
    seed_ids: list[str] = Field(max_length=100_000)
    reachable_ids: list[str] = Field(max_length=100_000)
    unresolved_ids: list[str] = Field(max_length=100_000)


class CompilerPropertyReachability(StrictModel):
    """Complete bounded structural closure; serialized declarations grant no authority."""

    schema_version: Literal["1.0"] = "1.0"
    project_root: str = Field(min_length=1, max_length=1_000)
    inventory_sha256: str = Field(pattern=_SHA)
    corpus_hash: str = Field(pattern=_SHA)
    build_info_sha256s: list[str] = Field(min_length=1, max_length=1_000)
    sources: list[FoundryInventorySourceBinding] = Field(min_length=1, max_length=100_000)
    regions: list[CompilerPropertyRegion] = Field(max_length=100_000)
    references: list[CompilerPropertyReference] = Field(max_length=200_000)
    unresolved: list[UnresolvedCompilerPropertyReference] = Field(max_length=200_000)
    properties: list[CompilerPropertyReachabilityRow] = Field(max_length=10_000)
    limits: PropertyReachabilityLimits
    evidence_authority: Literal["COLLECTED_UNATTESTED"] = "COLLECTED_UNATTESTED"
    path_feasibility_established: Literal[False] = False
    execution_validated: Literal[False] = False
    qualification_eligible: Literal[False] = False
    reachability_sha256: str = Field(pattern=_SHA)

    @classmethod
    def sealed(cls, **values: Any) -> Self:
        if "reachability_sha256" in values:
            raise ValueError("compiler property reachability digest is derived")
        draft = cls.model_construct(**values, reachability_sha256="0" * 64)
        value = draft.model_dump(mode="json", exclude={"reachability_sha256"})
        return cls.model_validate({**value, "reachability_sha256": _hash(value)})

    @model_validator(mode="after")
    def exact_graph_and_closure(self) -> Self:
        if normalize_relative_path(self.project_root) != self.project_root:
            raise ValueError("compiler property graph project root is not canonical")
        builds = self.build_info_sha256s
        if builds != sorted(set(builds)) or any(
            len(b) != 64 or any(c not in "0123456789abcdef" for c in b) for b in builds
        ):
            raise ValueError("compiler property build population is not canonical")
        sources = {s.path: s for s in self.sources}
        for source in self.sources:
            source.validate_builds(builds)
        transformed_ids = {
            (s.path, b.build_info_sha256): b.source_id
            for s in self.sources
            for b in s.compiler_source_bindings
        }
        if list(sources) != sorted(sources) or len(sources) != len(self.sources):
            raise ValueError("compiler property sources must be unique and sorted")
        if any(not PurePosixPath(p).is_relative_to(self.project_root) for p in sources):
            raise ValueError("compiler property source differs from selected project")
        if (
            len(self.regions) + len(self.references) + len(self.unresolved)
            > self.limits.maximum_graph_items
        ):
            raise ValueError("compiler property graph exceeds its item bound")
        for population in (self.regions, self.references, self.unresolved):
            ids = [x.id for x in population]
            if ids != sorted(set(ids)):
                raise ValueError("compiler property graph identities must be unique and sorted")
        regions = {r.id: r for r in self.regions}
        identities: set[tuple[str, int]] = set()
        spans: dict[tuple[str, str], list[tuple[int, int]]] = defaultdict(list)
        source_ids: dict[tuple[str, int], str] = {}
        for r in self.regions:
            identity = r.build_info_sha256, r.ast_node_id
            source_key = r.build_info_sha256, r.source_id
            if (
                identity in identities
                or r.build_info_sha256 not in builds
                or r.path not in sources
                or not 0 <= r.start_byte < r.end_byte_exclusive <= sources[r.path].size_bytes
                or r.end_line < r.start_line
                or source_ids.get(source_key, r.path) != r.path
                or transformed_ids.get((r.path, r.build_info_sha256), r.source_id) != r.source_id
            ):
                raise ValueError("compiler property region has conflicting source/build identity")
            identities.add(identity)
            source_ids[source_key] = r.path
            spans[r.build_info_sha256, r.path].append((r.start_byte, r.end_byte_exclusive))
        for items in spans.values():
            ordered = sorted(items)
            if any(a[1] > b[0] for a, b in pairwise(ordered)):
                raise ValueError("compiler property callable regions overlap")
        callsites: set[tuple[str, int]] = set()
        calls: list[CompilerPropertyReference | UnresolvedCompilerPropertyReference] = [
            *self.references,
            *self.unresolved,
        ]
        for call in calls:
            caller = regions.get(call.caller_id)
            if (
                caller is None
                or not caller.start_byte
                <= call.start_byte
                < call.end_byte_exclusive
                <= caller.end_byte_exclusive
            ):
                raise ValueError("compiler property call differs from its containing callable")
            key = caller.build_info_sha256, call.ast_node_id
            if key in callsites:
                raise ValueError("compiler property call has ambiguous resolved/unresolved status")
            callsites.add(key)
            if isinstance(call, CompilerPropertyReference):
                target = regions.get(call.target_id)
                if (
                    target is None
                    or target.build_info_sha256 != caller.build_info_sha256
                    or target.virtual
                    or target.kind
                    != (
                        "ModifierDefinition"
                        if call.kind == "MODIFIER_INVOCATION"
                        else "FunctionDefinition"
                    )
                ):
                    raise ValueError(
                        "compiler property reference crosses an unresolved declaration"
                    )
        ids = [p.property_id for p in self.properties]
        if ids != sorted(set(ids)):
            raise ValueError("compiler property closure population must be unique and sorted")
        expected = _closures(
            [(p.property_id, p.seed_ids) for p in self.properties],
            self.regions,
            self.references,
            self.unresolved,
            self.limits,
        )
        if self.properties != expected:
            raise ValueError("compiler property closure omits or invents reachable scope")
        if self.reachability_sha256 != _hash(
            self.model_dump(mode="json", exclude={"reachability_sha256"})
        ):
            raise ValueError("compiler property reachability digest differs")
        return self

    def validate_corpus(self, corpus: PropertyCorpus) -> None:
        if self.corpus_hash != corpus.corpus_hash or [
            (p.property_id, p.seed_ids) for p in self.properties
        ] != _seeds(corpus, self.regions, self.limits):
            raise ValueError(
                "compiler property seeds differ from complete original source evidence"
            )

    def reachable_spans(self) -> dict[str, dict[tuple[str, str], tuple[list[int], list[int]]]]:
        regions = {r.id: r for r in self.regions}
        result = {}
        for prop in self.properties:
            spans: dict[tuple[str, str], list[tuple[int, int]]] = defaultdict(list)
            for identity in prop.reachable_ids:
                r = regions[identity]
                spans[r.build_info_sha256, r.path].append((r.start_byte, r.end_byte_exclusive))
            result[prop.property_id] = {
                key: ([x[0] for x in sorted(items)], [x[1] for x in sorted(items)])
                for key, items in spans.items()
            }
        return result


def _seeds(
    corpus: PropertyCorpus,
    regions: list[CompilerPropertyRegion],
    limits: PropertyReachabilityLimits,
) -> list[tuple[str, list[str]]]:
    by_path: dict[str, list[CompilerPropertyRegion]] = defaultdict(list)
    for region in regions:
        by_path[region.path].append(region)
    checked = 0
    result = []
    for prop in corpus.properties:
        ids = set()
        for evidence in prop.source_evidence:
            loc = evidence.location
            for r in by_path[loc.path]:
                checked += 1
                if checked > limits.maximum_seed_checks:
                    raise ValueError("compiler property seed comparison bound exceeded")
                if r.start_line <= loc.start_line <= loc.end_line <= r.end_line:
                    ids.add(r.id)
        result.append((prop.id, sorted(ids)))
    return result


def _closures(
    seeds: list[tuple[str, list[str]]],
    regions: list[CompilerPropertyRegion],
    references: list[CompilerPropertyReference],
    unresolved: list[UnresolvedCompilerPropertyReference],
    limits: PropertyReachabilityLimits,
) -> list[CompilerPropertyReachabilityRow]:
    known = {r.id for r in regions}
    adjacency: dict[str, list[str]] = defaultdict(list)
    gaps: dict[str, list[str]] = defaultdict(list)
    for edge in references:
        adjacency[edge.caller_id].append(edge.target_id)
    for gap in unresolved:
        gaps[gap.caller_id].append(gap.id)
    work = 0
    result = []
    for property_id, roots in seeds:
        if roots != sorted(set(roots)) or not set(roots) <= known:
            raise ValueError("compiler property seed population is ambiguous or absent")
        visited: set[str] = set()
        missing: set[str] = set()
        pending = list(roots)
        while pending:
            work += 1
            if work > limits.maximum_property_relations:
                raise ValueError("compiler property closure work bound exceeded")
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            pending.extend(adjacency[current])
            missing.update(gaps[current])
            work += len(gaps[current])
        if work > limits.maximum_property_relations:
            raise ValueError("compiler property closure work bound exceeded")
        result.append(
            CompilerPropertyReachabilityRow(
                property_id=property_id,
                seed_ids=roots,
                reachable_ids=sorted(visited),
                unresolved_ids=sorted(missing),
            )
        )
    return result


def _identified[T: _Identified](model: type[T], **values: Any) -> T:
    return model.model_validate({**values, "id": _hash(values)})


def derive_compiler_property_reachability(
    *,
    inventory_result: FoundryInventoryRunResult,
    project_root: str,
    corpus: PropertyCorpus,
    limits: PropertyReachabilityLimits | None = None,
) -> CompilerPropertyReachability:
    """Resolve only original direct nonvirtual internal calls/modifiers, without executing them."""

    bounds = PropertyReachabilityLimits.model_validate(
        (limits or PropertyReachabilityLimits()).model_dump()
    )
    corpus = PropertyCorpus.model_validate(corpus.model_dump(mode="python"))
    snapshot, evidence = validated_foundry_compiler_input(
        inventory_result, project_root=project_root
    )
    catalog = next(c for c in inventory_result.statement_catalogs if c.project_root == project_root)
    sources = {
        (PurePosixPath(project_root) / s.path).as_posix(): s.content for s in snapshot.sources
    }
    for prop in corpus.properties:
        for item in prop.source_evidence:
            loc = item.location
            raw = sources.get(loc.path)
            if (
                raw is None
                or loc.end_line > len(raw.decode("utf-8").splitlines())
                or line_range_hash(raw.decode("utf-8"), loc.start_line, loc.end_line)
                != loc.content_hash
            ):
                raise ValueError("compiler property source evidence differs from original bytes")
    payloads = {
        hashlib.sha256(raw).hexdigest(): json.loads(raw) for raw in snapshot.build_info_jsons
    }
    regions: list[CompilerPropertyRegion] = []
    references: list[CompilerPropertyReference] = []
    unresolved: list[UnresolvedCompilerPropertyReference] = []
    for unit in catalog.units:
        nodes = _nodes(
            payloads[unit.normalized_build_info_sha256],
            {s.path: s.source_mapping for s in unit.sources if s.source_mapping is not None},
        )
        local: dict[int, CompilerPropertyRegion] = {}
        raw_sources = {s.path: s.content for s in unit.sources}
        line_starts = {
            p: [0, *[i + 1 for i, value in enumerate(raw) if value == 10]]
            for p, raw in raw_sources.items()
        }
        for node in nodes.values():
            if node.kind not in {"FunctionDefinition", "ModifierDefinition"} or not isinstance(
                node.value.get("body"), dict
            ):
                continue
            parent = nodes.get(node.parent) if node.parent is not None else None
            if (
                parent is None
                or parent.kind not in {"ContractDefinition", "SourceUnit"}
                or (node.kind == "FunctionDefinition" and node.value.get("scope") != parent.id)
                or (
                    node.kind == "ModifierDefinition"
                    and (
                        parent.kind != "ContractDefinition"
                        or (
                            "scope" in node.value
                            and (
                                type(node.value["scope"]) is not int
                                or node.value["scope"] != parent.id
                            )
                        )
                    )
                )
                or type(node.value.get("virtual")) is not bool
            ):
                raise ValueError("compiler property callable declaration scope is malformed")
            local[node.id] = _identified(
                CompilerPropertyRegion,
                build_info_sha256=unit.normalized_build_info_sha256,
                ast_node_id=node.id,
                source_id=node.source_id,
                path=(PurePosixPath(project_root) / node.path).as_posix(),
                start_byte=node.start,
                end_byte_exclusive=node.end,
                start_line=bisect_right(line_starts[node.path], node.start),
                end_line=bisect_right(line_starts[node.path], node.end - 1),
                kind=node.kind,
                virtual=node.value["virtual"],
            )
        regions.extend(local.values())
        if len(regions) + len(references) + len(unresolved) > bounds.maximum_graph_items:
            raise ValueError("compiler property graph exceeds its item bound")
        owners: dict[int, int | None] = {}
        for node in nodes.values():
            owners[node.id] = (
                node.id
                if node.id in local
                else owners.get(node.parent)
                if node.parent is not None
                else None
            )
        for node in nodes.values():
            if node.kind not in {"FunctionCall", "ModifierInvocation", "InlineAssembly"}:
                continue
            owner = owners[node.id]
            if owner is None:
                continue
            expression = node.value.get(
                "modifierName" if node.kind == "ModifierInvocation" else "expression", {}
            )
            reference = (
                expression.get("referencedDeclaration") if isinstance(expression, dict) else None
            )
            if node.kind == "FunctionCall" and (
                node.value.get("kind") in {"typeConversion", "structConstructorCall"}
                or (type(reference) is int and reference < 0)
            ):
                continue
            target = local.get(reference) if type(reference) is int else None
            target_node = nodes.get(reference) if type(reference) is int else None
            name = expression.get("name") if isinstance(expression, dict) else None
            valid = (
                target is not None
                and target_node is not None
                and not target.virtual
                and name == target_node.value.get("name")
            )
            if node.kind == "ModifierInvocation":
                valid = (
                    valid
                    and expression.get("nodeType") in {"Identifier", "IdentifierPath"}
                    and target is not None
                    and target.kind == "ModifierDefinition"
                )
            else:
                valid = (
                    valid
                    and node.kind == "FunctionCall"
                    and expression.get("nodeType") == "Identifier"
                    and target is not None
                    and target.kind == "FunctionDefinition"
                    and str(
                        expression.get("typeDescriptions", {}).get("typeIdentifier", "")
                    ).startswith("t_function_internal_")
                )
            values = dict(
                caller_id=local[owner].id,
                ast_node_id=node.id,
                start_byte=node.start,
                end_byte_exclusive=node.end,
            )
            if valid and target is not None:
                references.append(
                    _identified(
                        CompilerPropertyReference,
                        **values,
                        target_id=target.id,
                        kind="MODIFIER_INVOCATION"
                        if node.kind == "ModifierInvocation"
                        else "DIRECT_INTERNAL_CALL",
                    )
                )
            else:
                unresolved.append(
                    _identified(
                        UnresolvedCompilerPropertyReference,
                        **values,
                        reason="INLINE_ASSEMBLY"
                        if node.kind == "InlineAssembly"
                        else "UNRESOLVED_OR_VIRTUAL_MODIFIER"
                        if node.kind == "ModifierInvocation"
                        else "UNRESOLVED_OR_DYNAMIC_CALL",
                    )
                )
            if len(regions) + len(references) + len(unresolved) > bounds.maximum_graph_items:
                raise ValueError("compiler property graph exceeds its item bound")
    regions.sort(key=lambda r: r.id)
    references.sort(key=lambda r: r.id)
    unresolved.sort(key=lambda r: r.id)
    result = CompilerPropertyReachability.sealed(
        project_root=project_root,
        inventory_sha256=evidence.normalized_inventory_sha256,
        corpus_hash=corpus.corpus_hash,
        build_info_sha256s=sorted(payloads),
        sources=[
            s.model_copy(update={"path": (PurePosixPath(project_root) / s.path).as_posix()})
            for s in compiler_catalog_source_bindings(catalog)
        ],
        regions=regions,
        references=references,
        unresolved=unresolved,
        properties=_closures(
            _seeds(corpus, regions, bounds), regions, references, unresolved, bounds
        ),
        limits=bounds,
    )
    result.validate_corpus(corpus)
    return result
