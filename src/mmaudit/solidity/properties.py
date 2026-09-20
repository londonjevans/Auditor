"""Engine-neutral property corpus construction from the typed invariant DSL."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import Field, model_validator

from mmaudit.models.schemas import (
    AnalysisState,
    DynamicPropertySpec,
    ForkArgumentKind,
    FoundryInvariantHarnessSpec,
    HarnessArgumentSource,
    InvariantSpec,
    InvariantSuite,
    PropertyCampaignBounds,
    PropertyCorpus,
    PropertyFuzzInputBound,
    PropertySourceEvidence,
    RepositorySuiteInventoryRecord,
    SolidityEntity,
    SolidityProvenance,
    SoliditySymbolIndex,
    StrictModel,
)
from mmaudit.repository.chunking import line_range_hash
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.solidity.property_reachability import (
    CompilerPropertyReachability,
    derive_compiler_property_reachability,
)

if TYPE_CHECKING:
    from mmaudit.scanners.foundry_inventory_runner import FoundryInventoryRunResult


@dataclass
class _MutableFuzzBound:
    kind: ForkArgumentKind
    minimum: int | None
    maximum: int | None
    sources: set[str]


def build_property_corpus(
    suite: InvariantSuite | None,
    index: SoliditySymbolIndex | None,
    harnesses: list[FoundryInvariantHarnessSpec],
) -> PropertyCorpus:
    """Build stable properties only when invariant and exact source evidence resolve."""

    limitations: list[str] = []
    properties_by_id: dict[str, DynamicPropertySpec] = {}
    if suite is None or index is None:
        limitations.append("property corpus requires a Solidity invariant suite and symbol index")
        return _corpus([], limitations)

    invariants = {invariant.id: invariant for invariant in suite.invariants}
    entities = {entity.id: entity for entity in index.entities}
    for harness in sorted(harnesses, key=lambda item: (item.invariant_id, item.name)):
        invariant = invariants.get(harness.invariant_id)
        if invariant is None:
            limitations.append(
                f"{harness.invariant_id}/{harness.name}: referenced invariant is unavailable"
            )
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", invariant.evidence_hash):
            limitations.append(
                f"{harness.invariant_id}/{harness.name}: invariant evidence hash is invalid"
            )
            continue
        if (
            invariant.provenance is SolidityProvenance.MODEL_SUGGESTED
            or invariant.analysis_state is AnalysisState.MODEL_ONLY
        ):
            limitations.append(
                f"{harness.invariant_id}/{harness.name}: model-only invariant is not executable"
            )
            continue
        if not invariant.executable:
            limitations.append(
                f"{harness.invariant_id}/{harness.name}: invariant is not marked executable"
            )
            continue
        resolved, missing = _source_entities(invariant, entities)
        if missing:
            limitations.append(
                f"{harness.invariant_id}/{harness.name}: unresolved source entities "
                + ", ".join(missing)
            )
            continue
        if not resolved:
            limitations.append(
                f"{harness.invariant_id}/{harness.name}: exact source evidence is unavailable"
            )
            continue
        invariant_locations = {
            (
                location.path,
                location.start_line,
                location.end_line,
                location.content_hash,
            )
            for location in invariant.locations
        }
        unlinked = [
            entity.id
            for entity in resolved
            if (
                entity.path,
                entity.start_line,
                entity.end_line,
                entity.source_hash,
            )
            not in invariant_locations
        ]
        if unlinked:
            limitations.append(
                f"{harness.invariant_id}/{harness.name}: source location mismatch for "
                + ", ".join(unlinked)
            )
            continue
        try:
            campaign = _campaign_bounds(harness)
        except ValueError as exc:
            limitations.append(f"{harness.invariant_id}/{harness.name}: {exc}")
            continue
        source_evidence = [
            PropertySourceEvidence(
                entity_id=entity.id,
                location={
                    "path": entity.path,
                    "start_line": entity.start_line,
                    "end_line": entity.end_line,
                    "symbol": entity.name,
                    "content_hash": entity.source_hash,
                },
                provenance=entity.provenance,
                confidence=entity.confidence,
                transformation=entity.transformation,
            )
            for entity in resolved
        ]
        targets = _target_aliases(harness)
        covered_functions = _covered_functions(invariant, harness)
        assumptions = sorted(set([*invariant.assumptions, *harness.assumptions]))
        confidence = min(
            invariant.confidence,
            *(evidence.confidence for evidence in source_evidence),
        )
        for predicate in sorted(harness.properties, key=lambda item: item.property_id):
            property_values: dict[str, Any] = {
                "invariant_id": invariant.id,
                "harness_name": harness.name,
                "property_id": predicate.property_id,
                "title": invariant.title,
                "description": invariant.description,
                "category": invariant.category,
                "template": invariant.template,
                "predicate": predicate,
                "actors": harness.actors,
                "setup_calls": harness.setup_calls,
                "token_balance_seeds": harness.token_balance_seeds,
                "actions": harness.actions,
                "target_aliases": targets,
                "source_evidence": source_evidence,
                "covered_entity_ids": [evidence.entity_id for evidence in source_evidence],
                "covered_functions": covered_functions,
                "covered_state_variables": sorted(set(invariant.state_variables)),
                "assumptions": assumptions,
                "provenance": invariant.provenance,
                "confidence": confidence,
                "analysis_state": invariant.analysis_state,
                "campaign": campaign,
                "capability_policy": harness.capability_policy,
                "invariant_evidence_hash": invariant.evidence_hash,
            }
            draft = DynamicPropertySpec.model_construct(
                id="prop-" + ("0" * 24),
                property_hash="0" * 64,
                **property_values,
            )
            property_hash = DynamicPropertySpec.calculate_hash(draft.model_dump(mode="json"))
            shared = DynamicPropertySpec(
                id=f"prop-{property_hash[:24]}",
                property_hash=property_hash,
                **property_values,
            )
            if shared.id in properties_by_id:
                limitations.append(
                    f"{harness.invariant_id}/{harness.name}/{predicate.property_id}: "
                    "duplicate shared property was omitted"
                )
                continue
            properties_by_id[shared.id] = shared
    return _corpus(list(properties_by_id.values()), limitations)


def _source_entities(
    invariant: InvariantSpec,
    entities: dict[str, SolidityEntity],
) -> tuple[list[SolidityEntity], list[str]]:
    requested_ids = sorted(set(invariant.entity_ids))
    missing = [entity_id for entity_id in requested_ids if entity_id not in entities]
    return [entities[entity_id] for entity_id in requested_ids if entity_id in entities], missing


def _target_aliases(harness: FoundryInvariantHarnessSpec) -> list[str]:
    targets = {
        *(call.target for call in harness.setup_calls),
        *(action.target for action in harness.actions),
        *(property_spec.left.target for property_spec in harness.properties),
        *(
            property_spec.right.target
            for property_spec in harness.properties
            if property_spec.right is not None
        ),
        *(seed.token for seed in harness.token_balance_seeds),
    }
    return sorted(targets)


def _covered_functions(
    invariant: InvariantSpec,
    harness: FoundryInvariantHarnessSpec,
) -> list[str]:
    functions = {
        *invariant.functions,
        *(call.function_signature for call in harness.setup_calls),
        *(action.function_signature for action in harness.actions),
        *(property_spec.left.function_signature for property_spec in harness.properties),
        *(
            property_spec.right.function_signature
            for property_spec in harness.properties
            if property_spec.right is not None
        ),
    }
    return sorted(functions)


def _campaign_bounds(harness: FoundryInvariantHarnessSpec) -> PropertyCampaignBounds:
    bounds: dict[int, _MutableFuzzBound] = {}
    for action in harness.actions:
        if action.actor_fuzz_slot is not None:
            _add_fuzz_bound(
                bounds,
                slot=action.actor_fuzz_slot,
                kind=ForkArgumentKind.ADDRESS,
                minimum=None,
                maximum=None,
                source=f"{action.action_id}:actor",
            )
        for position, argument in enumerate(action.arguments):
            if argument.source is HarnessArgumentSource.CONSTANT:
                continue
            if argument.fuzz_slot is None:
                raise ValueError(f"{action.action_id}: fuzz argument lacks a slot")
            _add_fuzz_bound(
                bounds,
                slot=argument.fuzz_slot,
                kind=argument.kind,
                minimum=argument.minimum,
                maximum=argument.maximum,
                source=f"{action.action_id}:argument[{position}]",
            )
    fuzz_inputs = [
        PropertyFuzzInputBound(
            slot=slot,
            kind=bound.kind,
            minimum=bound.minimum,
            maximum=bound.maximum,
            sources=sorted(bound.sources),
        )
        for slot, bound in sorted(bounds.items())
    ]
    maximum_time_shift = (
        max((action.time_shift_seconds_before for action in harness.actions), default=0)
        * harness.depth
    )
    return PropertyCampaignBounds(
        seed=harness.seed,
        runs=harness.runs,
        depth=harness.depth,
        fuzz_inputs=fuzz_inputs,
        maximum_time_shift_seconds=maximum_time_shift,
        maximum_call_value_wei=max(
            (
                *(call.value_wei for call in harness.setup_calls),
                *(action.value_wei for action in harness.actions),
            ),
            default=0,
        ),
        maximum_actor_initial_balance_wei=max(
            (actor.initial_native_balance_wei for actor in harness.actors),
            default=0,
        ),
        maximum_token_seed_amount=max(
            (seed.amount for seed in harness.token_balance_seeds),
            default=0,
        ),
        transaction_ordering=harness.required_transaction_ordering,
    )


def _add_fuzz_bound(
    bounds: dict[int, _MutableFuzzBound],
    *,
    slot: int,
    kind: ForkArgumentKind,
    minimum: int | None,
    maximum: int | None,
    source: str,
) -> None:
    existing = bounds.get(slot)
    if existing is None:
        bounds[slot] = _MutableFuzzBound(
            kind=kind,
            minimum=minimum,
            maximum=maximum,
            sources={source},
        )
        return
    if (existing.kind, existing.minimum, existing.maximum) != (kind, minimum, maximum):
        raise ValueError(f"fuzz slot {slot} has conflicting type or numeric bounds")
    existing.sources.add(source)


def _corpus(
    properties: list[DynamicPropertySpec],
    limitations: list[str],
) -> PropertyCorpus:
    ordered_properties = sorted(properties, key=lambda item: item.id)
    ordered_limitations = sorted(set(limitations))
    payload = {
        "schema_version": "1.0",
        "property_hashes": [item.property_hash for item in ordered_properties],
        "limitations": ordered_limitations,
    }
    return PropertyCorpus(
        properties=ordered_properties,
        limitations=ordered_limitations,
        corpus_hash=_stable_hash(payload),
    )


def _stable_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class CompilerBoundPropertyTest(StrictModel):
    """An exact generated assertion, not an inference from a test's name."""

    property_id: str = Field(pattern=r"^prop-[0-9a-f]{24}$")
    record: RepositorySuiteInventoryRecord
    test_id: str = Field(min_length=1, max_length=200)


class FoundryPropertyTestMapping(StrictModel):
    """Complete property/test accounting; consistency grants no runtime or truth authority."""

    corpus: PropertyCorpus
    project_root: str = Field(min_length=1, max_length=1_000)
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_chain_id: int | None = Field(
        default=None, ge=1, le=2**256 - 1, exclude_if=lambda value: value is None
    )
    harnesses: list[FoundryInvariantHarnessSpec] = Field(max_length=10_000)
    tests: list[CompilerBoundPropertyTest] = Field(max_length=10_000)
    unresolved_property_ids: list[str] = Field(max_length=10_000)
    compiler_reachability: CompilerPropertyReachability | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    execution_validated: Literal[False] = False
    qualification_eligible: Literal[False] = False
    mapping_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> Self:
        if "mapping_sha256" in values:
            raise ValueError("property mapping digest is derived")
        draft = cls.model_construct(**values, mapping_sha256="0" * 64)
        payload = draft.model_dump(mode="json", exclude={"mapping_sha256"})
        return cls.model_validate({**payload, "mapping_sha256": _stable_hash(payload)})

    @model_validator(mode="after")
    def exact_generated_assertions_and_population(self) -> Self:
        from mmaudit.benchmark.foundry_mutation_executor import (
            canonical_foundry_inventory_mutation_test_id,
        )

        if normalize_relative_path(self.project_root) != self.project_root:
            raise ValueError("property mapping project root is not canonical")
        names = [h.name for h in self.harnesses]
        if names != sorted(set(names)):
            raise ValueError("generated property harness names must be unique and sorted")
        properties = {p.id: p for p in self.corpus.properties}
        if self.compiler_reachability is not None:
            self.compiler_reachability.validate_corpus(self.corpus)
            if (
                self.compiler_reachability.project_root != self.project_root
                or self.compiler_reachability.inventory_sha256 != self.inventory_sha256
            ):
                raise ValueError("compiler property reachability differs from selected inventory")
        bound_ids = [t.property_id for t in self.tests]
        missing = self.unresolved_property_ids
        if (
            bound_ids != sorted(set(bound_ids))
            or missing != sorted(set(missing))
            or set(bound_ids) & set(missing)
            or set(bound_ids) | set(missing) != set(properties)
        ):
            raise ValueError("every corpus property requires one bound test or unresolved record")
        harnesses = {h.name: h for h in self.harnesses}
        generated = {
            h.name: generated_local_property_source(
                h, project_root=self.project_root, expected_chain_id=self.expected_chain_id
            )
            for h in self.harnesses
        }
        for test in self.tests:
            prop = properties[test.property_id]
            harness = harnesses.get(prop.harness_name)
            if harness is None:
                raise ValueError("bound property lacks its complete typed harness")
            _validate_property_harness(prop, harness)
            source = generated[harness.name]
            if source is None:
                raise ValueError("bound property requires locally deployed targets")
            path, content = source
            record = test.record
            suite = f"MMAuditInvariant_{harness.name}"
            name = f"invariant_{prop.property_id}"
            signature = name + "()"
            source_sha = hashlib.sha256(content).hexdigest()
            if (
                record.project_root != self.project_root
                or record.execution_path != path
                or record.declaration_path != path
                or record.execution_suite_name != suite
                or record.declaration_suite_name != suite
                or record.test_name != name
                or record.execution_signature not in {name, signature}
                or record.declaration_signature != signature
                or record.execution_source_sha256 != source_sha
                or record.declaration_source_sha256 != source_sha
                or test.test_id
                != canonical_foundry_inventory_mutation_test_id(
                    record, inventory_sha256=self.inventory_sha256
                )
            ):
                raise ValueError(
                    "compiled property test differs from the exact generated assertion"
                )
        if self.mapping_sha256 != _stable_hash(
            self.model_dump(mode="json", exclude={"mapping_sha256"})
        ):
            raise ValueError("property test mapping digest differs")
        return self


def generated_local_property_source(
    harness: FoundryInvariantHarnessSpec,
    *,
    project_root: str,
    expected_chain_id: int | None = None,
) -> tuple[str, bytes] | None:
    """Reproduce the existing runner's complete local harness; never execute or write it."""

    from mmaudit.solidity.invariant_execution import translate_foundry_invariant

    if type(harness) is not FoundryInvariantHarnessSpec:
        raise ValueError("property generation requires the exact typed harness")
    harness = FoundryInvariantHarnessSpec.model_validate(harness.model_dump(mode="python"))
    if normalize_relative_path(project_root) != project_root:
        raise ValueError("generated property project root is not canonical")
    if expected_chain_id is not None and (
        type(expected_chain_id) is not int or not 1 <= expected_chain_id <= 2**256 - 1
    ):
        raise ValueError("generated property chain identity is invalid")
    if not harness.local_deployments:
        return None
    if any(
        re.fullmatch(r"[A-Za-z0-9_./@-]+\.sol", item.source_path) is None
        for item in harness.local_deployments
    ):
        raise ValueError("local property import path cannot be safely rendered in Solidity")
    # Every referenced alias is local by the harness validator. No address is contacted.
    targets = {item.target_alias: "0x" + "0" * 40 for item in harness.local_deployments}
    source = translate_foundry_invariant(
        harness, targets=targets, expected_chain_id=expected_chain_id
    )
    path = (
        PurePosixPath(project_root)
        / "test/mmaudit_generated"
        / f"MMAuditInvariant_{harness.name}.t.sol"
    ).as_posix()
    return path, source.encode("utf-8")


def _validate_property_harness(
    prop: DynamicPropertySpec, harness: FoundryInvariantHarnessSpec
) -> None:
    if (
        prop.invariant_id != harness.invariant_id
        or prop.harness_name != harness.name
        or prop.predicate not in harness.properties
        or prop.actors != harness.actors
        or prop.setup_calls != harness.setup_calls
        or prop.token_balance_seeds != harness.token_balance_seeds
        or prop.actions != harness.actions
        or prop.target_aliases != _target_aliases(harness)
        or prop.campaign != _campaign_bounds(harness)
        or prop.capability_policy != harness.capability_policy
        or not set(harness.assumptions) <= set(prop.assumptions)
    ):
        raise ValueError("property predicate, actions, actors or campaign differ from its harness")


def bind_compiled_property_tests(
    *,
    inventory_result: FoundryInventoryRunResult,
    project_root: str,
    corpus: PropertyCorpus,
    harnesses: list[FoundryInvariantHarnessSpec],
    expected_chain_id: int | None = None,
    include_compiler_reachability: bool = True,
) -> FoundryPropertyTestMapping:
    """Join exact source-backed predicates to original compiler-inventoried local assertions.

    Missing assertions remain unresolved. Changed source or conflicting typed inputs are
    refused, not downgraded to an omission. No filesystem, process or network I/O occurs.
    """

    from mmaudit.benchmark.foundry_mutation_executor import (
        canonical_foundry_inventory_mutation_test_id,
    )
    from mmaudit.models.schemas import RepositorySuiteInventoryPhase
    from mmaudit.scanners.foundry_inventory_runner import validated_foundry_compiler_input

    if (
        type(corpus) is not PropertyCorpus
        or type(harnesses) is not list
        or type(include_compiler_reachability) is not bool
    ):
        raise ValueError("property mapping requires exact typed corpus and harness inputs")
    corpus = PropertyCorpus.model_validate(corpus.model_dump(mode="python"))
    if len(harnesses) > 10_000 or any(
        type(h) is not FoundryInvariantHarnessSpec for h in harnesses
    ):
        raise ValueError("property harness population is invalid or excessive")
    harnesses = [
        FoundryInvariantHarnessSpec.model_validate(h.model_dump(mode="python")) for h in harnesses
    ]
    harnesses.sort(key=lambda h: h.name)
    if len({h.name for h in harnesses}) != len(harnesses):
        raise ValueError("generated property harness names are ambiguous")
    snapshot, inventory = validated_foundry_compiler_input(
        inventory_result, project_root=project_root
    )
    if inventory.phase is not RepositorySuiteInventoryPhase.PRE_EXECUTION:
        raise ValueError("property mapping requires pre-execution compiler inventory")
    sources = {
        (PurePosixPath(project_root) / s.path).as_posix(): s.content for s in snapshot.sources
    }
    for prop in corpus.properties:
        for evidence in prop.source_evidence:
            location = evidence.location
            raw = sources.get(location.path)
            if raw is None:
                raise ValueError("property evidence source is absent from retained compiler input")
            content = raw.decode("utf-8", errors="strict")
            if (
                location.end_line > len(content.splitlines())
                or line_range_hash(content, location.start_line, location.end_line)
                != location.content_hash
            ):
                raise ValueError("property evidence differs from exact retained source lines")
    by_name = {h.name: h for h in harnesses}
    generated = {
        h.name: generated_local_property_source(
            h, project_root=project_root, expected_chain_id=expected_chain_id
        )
        for h in harnesses
    }
    for source in generated.values():
        if source is not None and source[0] in sources and sources[source[0]] != source[1]:
            raise ValueError("retained property harness differs from complete generated source")
    project = next(p for p in inventory.projects if p.project_root == project_root)
    tests: list[CompilerBoundPropertyTest] = []
    unresolved: list[str] = []
    for prop in corpus.properties:
        harness = by_name.get(prop.harness_name)
        source = None if harness is None else generated[harness.name]
        if harness is not None:
            _validate_property_harness(prop, harness)
        records = (
            [
                r
                for r in project.records
                if r.execution_path == source[0]
                and r.execution_suite_name == f"MMAuditInvariant_{prop.harness_name}"
                and r.test_name == f"invariant_{prop.property_id}"
            ]
            if source is not None and source[0] in sources
            else []
        )
        if len(records) > 1:
            raise ValueError("generated property assertion has ambiguous compiler records")
        if not records:
            unresolved.append(prop.id)
            continue
        tests.append(
            CompilerBoundPropertyTest(
                property_id=prop.id,
                record=records[0],
                test_id=canonical_foundry_inventory_mutation_test_id(
                    records[0], inventory_sha256=inventory.normalized_inventory_sha256
                ),
            )
        )
    return FoundryPropertyTestMapping.sealed(
        corpus=corpus,
        project_root=project_root,
        inventory_sha256=inventory.normalized_inventory_sha256,
        expected_chain_id=expected_chain_id,
        harnesses=harnesses,
        tests=tests,
        unresolved_property_ids=unresolved,
        compiler_reachability=(
            derive_compiler_property_reachability(
                inventory_result=inventory_result, project_root=project_root, corpus=corpus
            )
            if include_compiler_reachability
            else None
        ),
    )
