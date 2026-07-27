"""Deterministic validation for model-proposed Solidity invariants."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from mmaudit.models.schemas import (
    AnalysisState,
    InvariantProposalRejection,
    InvariantReviewBatch,
    InvariantReviewResult,
    InvariantSpec,
    Location,
    SolidityEntityKind,
    SolidityProvenance,
    SoliditySymbolIndex,
)
from mmaudit.repository.locations import validate_location

_FUNCTION_KINDS = {
    SolidityEntityKind.FUNCTION,
    SolidityEntityKind.CONSTRUCTOR,
    SolidityEntityKind.MODIFIER,
}
_STATE_KINDS = {
    SolidityEntityKind.STATE_VARIABLE,
    SolidityEntityKind.IMMUTABLE,
    SolidityEntityKind.CONSTANT,
}


def validate_invariant_review(
    repository_root: Path,
    batch: InvariantReviewBatch,
    *,
    index: SoliditySymbolIndex | None,
    context_hashes: dict[tuple[str, int, int], str],
) -> InvariantReviewResult:
    """Accept only proposals anchored to supplied, unchanged source and indexed symbols.

    Accepted proposals intentionally remain model-only and non-executable. A later,
    separately trusted translation step would be required before they could become
    a property test.
    """

    entities_by_id = {entity.id: entity for entity in (index.entities if index else [])}
    function_names = {
        entity.name for entity in entities_by_id.values() if entity.kind in _FUNCTION_KINDS
    }
    state_names = {entity.name for entity in entities_by_id.values() if entity.kind in _STATE_KINDS}
    accepted: dict[str, InvariantSpec] = {}
    rejected: list[InvariantProposalRejection] = []

    for proposal in batch.proposals:
        errors: list[str] = []
        validated_locations: list[Location] = []
        if index is None:
            errors.append("normalized Solidity symbol index is unavailable")
        if not proposal.entity_ids:
            errors.append("proposal must reference at least one indexed Solidity entity")
        unknown_entities = sorted(set(proposal.entity_ids) - set(entities_by_id))
        if unknown_entities:
            errors.append("unknown indexed entity IDs: " + ", ".join(unknown_entities))
        unknown_functions = sorted(set(proposal.functions) - function_names)
        if unknown_functions:
            errors.append("unknown indexed function names: " + ", ".join(unknown_functions))
        unknown_state = sorted(set(proposal.state_variables) - state_names)
        if unknown_state:
            errors.append("unknown indexed state-variable names: " + ", ".join(unknown_state))

        for location in proposal.locations:
            validation = validate_location(
                repository_root,
                location,
                context_hashes=context_hashes,
            )
            errors.extend(
                f"{location.path}:{location.start_line}: {error}" for error in validation.errors
            )
            if validation.valid and validation.content_hash is not None:
                validated_locations.append(
                    location.model_copy(update={"content_hash": validation.content_hash})
                )

        referenced_entities = [
            entities_by_id[entity_id]
            for entity_id in proposal.entity_ids
            if entity_id in entities_by_id
        ]
        if referenced_entities and not any(
            entity.path == location.path
            and entity.start_line <= location.end_line
            and entity.end_line >= location.start_line
            for entity in referenced_entities
            for location in validated_locations
        ):
            errors.append(
                "referenced indexed entities do not overlap a validated proposal location"
            )

        if errors:
            rejected.append(
                InvariantProposalRejection(
                    title=proposal.title,
                    errors=sorted(set(errors)),
                )
            )
            continue

        primary = validated_locations[0]
        stable_payload = {
            "category": proposal.category.value,
            "title": proposal.title.casefold().strip(),
            "path": primary.path,
            "start_line": primary.start_line,
            "entity_ids": sorted(set(proposal.entity_ids)),
        }
        stable_id = (
            "inv-model-"
            + hashlib.sha256(
                json.dumps(stable_payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()[:20]
        )
        evidence_payload = {
            **proposal.model_dump(mode="json"),
            "locations": [location.model_dump(mode="json") for location in validated_locations],
        }
        evidence_hash = hashlib.sha256(
            json.dumps(evidence_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if stable_id in accepted:
            rejected.append(
                InvariantProposalRejection(
                    title=proposal.title,
                    errors=["duplicate model invariant proposal after deterministic normalization"],
                )
            )
            continue
        accepted[stable_id] = InvariantSpec(
            id=stable_id,
            title=proposal.title,
            category=proposal.category,
            description=proposal.description,
            template=proposal.template,
            locations=validated_locations,
            entity_ids=sorted(set(proposal.entity_ids)),
            state_variables=sorted(set(proposal.state_variables)),
            functions=sorted(set(proposal.functions)),
            protocol_profiles=sorted(set(proposal.protocol_profiles)),
            assumptions=[*proposal.assumptions, f"Model rationale: {proposal.rationale}"],
            provenance=SolidityProvenance.MODEL_SUGGESTED,
            confidence=min(0.65, proposal.confidence),
            template_available=False,
            executable=False,
            analysis_state=AnalysisState.MODEL_ONLY,
            evidence_hash=evidence_hash,
        )

    return InvariantReviewResult(
        decisions=batch.decisions,
        accepted_proposals=sorted(
            accepted.values(),
            key=lambda item: (item.category.value, item.locations[0].path, item.id),
        ),
        rejected_proposals=rejected,
    )
