"""Fail-closed sealing for explicit, surface-specific model review evidence."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from mmaudit.constants import SPECIALIST_INVESTIGATOR_ROLES
from mmaudit.models.openrouter import StructuredCompletion, strict_json_schema
from mmaudit.models.schemas import (
    CandidateReviewBatch,
    ContextExcerpt,
    ContextPackage,
    Location,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
)
from mmaudit.models.usage import is_creditable_usage_record

_BASE_REVIEW_ROLES = frozenset({"source_audit", "business_logic", "configuration"})
_SPECIALIST_REVIEW_ROLES = frozenset(f"specialist:{role}" for role in SPECIALIST_INVESTIGATOR_ROLES)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ModelReviewEvidenceError(ValueError):
    """Raised when model-authored review evidence cannot be safely credited."""


def seal_model_surface_review_artifact(
    context: ContextPackage,
    completion: StructuredCompletion[CandidateReviewBatch],
) -> ModelSurfaceReviewArtifact | None:
    """Validate and hash-link one completed response to its exact requested surfaces."""

    if context.role not in _BASE_REVIEW_ROLES | _SPECIALIST_REVIEW_ROLES:
        raise ModelReviewEvidenceError(
            "model surface evidence was produced by a non-investigator role"
        )
    if not isinstance(completion.value, CandidateReviewBatch):
        raise ModelReviewEvidenceError(
            "model surface evidence did not use the candidate review schema"
        )

    usage = completion.usage_record
    if usage.role != context.role:
        raise ModelReviewEvidenceError(
            "model surface evidence usage role differs from the request context"
        )
    if not is_creditable_usage_record(usage):
        raise ModelReviewEvidenceError(
            "model surface evidence requires a completed creditable structured request"
        )
    if usage.schema_sha256 != _canonical_sha256(strict_json_schema(CandidateReviewBatch)):
        raise ModelReviewEvidenceError(
            "model surface evidence response schema hash is inconsistent"
        )
    if usage.validated_response_sha256 != _canonical_sha256(
        completion.value.model_dump(mode="json")
    ):
        raise ModelReviewEvidenceError(
            "model surface evidence validated response hash is inconsistent"
        )

    requests = tuple(context.requested_model_surfaces)
    requested_ids = tuple(request.surface_id for request in requests)
    if requested_ids != tuple(sorted(set(requested_ids))):
        raise ModelReviewEvidenceError("requested model surface IDs must be unique and sorted")

    records = tuple(completion.value.surface_reviews)
    record_ids = tuple(record.surface_id for record in records)
    if record_ids != tuple(sorted(set(record_ids))):
        raise ModelReviewEvidenceError("model surface review records must be unique and sorted")
    if record_ids != requested_ids:
        raise ModelReviewEvidenceError(
            "model surface review records do not exactly cover the requested surfaces"
        )
    if not requests:
        return None

    request_by_id = {request.surface_id: request for request in requests}
    for record in records:
        request = request_by_id[record.surface_id]
        validate_model_surface_review_record(
            request,
            record,
            expected_role=context.role,
        )
        if record.citation.location is not None:
            _validate_location_source(
                context=context,
                request=request,
                location=record.citation.location,
            )

    if (
        usage.response_sha256 is None
        or usage.validated_response_sha256 is None
        or usage.schema_sha256 is None
    ):
        raise ModelReviewEvidenceError("model surface evidence request hashes are incomplete")
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "request_id": usage.request_id,
        "review_role": context.role,
        "requested_surface_ids": list(requested_ids),
        "requested_surface_ids_sha256": _canonical_sha256(list(requested_ids)),
        "requested_surface_manifest_sha256": (
            ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(requests)
        ),
        "prompt_sha256": usage.prompt_sha256,
        "response_sha256": usage.response_sha256,
        "validated_response_sha256": usage.validated_response_sha256,
        "response_schema_sha256": usage.schema_sha256,
        "records": [record.model_dump(mode="json") for record in records],
    }
    payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(payload)
    try:
        artifact = ModelSurfaceReviewArtifact.model_validate(payload)
        artifact.require_exact_requested_surface_manifest(requests)
    except ValueError as exc:
        raise ModelReviewEvidenceError("model surface evidence artifact binding failed") from exc
    return artifact


def validate_model_surface_review_record(
    request: ModelSurfaceReviewRequest,
    record: ModelSurfaceReviewRecord,
    expected_role: str,
) -> None:
    """Revalidate one sealed record against a deterministic inventory descriptor."""

    if expected_role not in _BASE_REVIEW_ROLES | _SPECIALIST_REVIEW_ROLES:
        raise ModelReviewEvidenceError(
            "model surface evidence was produced by a non-investigator role"
        )
    _validate_record_metadata(
        request=request,
        record=record,
        expected_role=expected_role,
    )
    citation = record.citation
    if citation.location is not None:
        _validate_location_descriptor(request=request, location=citation.location)
    if citation.symbol is not None and citation.symbol not in request.allowed_symbols:
        raise ModelReviewEvidenceError(
            f"model surface {request.surface_id} cited an unrequested symbol"
        )


def _validate_record_metadata(
    *,
    request: ModelSurfaceReviewRequest,
    record: ModelSurfaceReviewRecord,
    expected_role: str,
) -> None:
    if record.surface_id != request.surface_id:
        raise ModelReviewEvidenceError("model surface record ID is inconsistent")
    if record.review_role != expected_role:
        raise ModelReviewEvidenceError(
            f"model surface {request.surface_id} review role is inconsistent"
        )
    if record.contract != request.contract:
        raise ModelReviewEvidenceError(
            f"model surface {request.surface_id} contract is inconsistent"
        )
    if record.function_or_state_surface != request.function_or_state_surface:
        raise ModelReviewEvidenceError(
            f"model surface {request.surface_id} function or state metadata is inconsistent"
        )
    if record.invariant_considered != request.invariant_considered:
        raise ModelReviewEvidenceError(
            f"model surface {request.surface_id} invariant metadata is inconsistent"
        )


def _validate_location_descriptor(
    *,
    request: ModelSurfaceReviewRequest,
    location: Location,
) -> None:
    if location.content_hash is None or _SHA256.fullmatch(location.content_hash) is None:
        raise ModelReviewEvidenceError(
            f"model surface {request.surface_id} location lacks an exact source hash"
        )
    if location not in request.allowed_locations:
        raise ModelReviewEvidenceError(
            f"model surface {request.surface_id} cited an unrequested source location"
        )


def _validate_location_source(
    *,
    context: ContextPackage,
    request: ModelSurfaceReviewRequest,
    location: Location,
) -> None:
    if not any(_excerpt_proves_location(excerpt, location) for excerpt in context.excerpts):
        raise ModelReviewEvidenceError(
            f"model surface {request.surface_id} source location hash was not proven by context"
        )


def _excerpt_proves_location(excerpt: ContextExcerpt, location: Location) -> bool:
    if (
        excerpt.path != location.path
        or excerpt.start_line > location.start_line
        or location.end_line > excerpt.end_line
        or hashlib.sha256(excerpt.content.encode()).hexdigest() != excerpt.content_hash
    ):
        return False
    relative_start = location.start_line - excerpt.start_line
    relative_end = location.end_line - excerpt.start_line + 1
    lines = excerpt.content.splitlines(keepends=True)
    if relative_end > len(lines):
        return False
    observed_hash = hashlib.sha256("".join(lines[relative_start:relative_end]).encode()).hexdigest()
    return observed_hash == location.content_hash


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()


__all__ = [
    "ModelReviewEvidenceError",
    "seal_model_surface_review_artifact",
    "validate_model_surface_review_record",
]
