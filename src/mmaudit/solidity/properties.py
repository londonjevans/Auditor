"""Engine-neutral property corpus construction from the typed invariant DSL."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

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
    SolidityEntity,
    SolidityProvenance,
    SoliditySymbolIndex,
)


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
