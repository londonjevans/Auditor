from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    CandidateReviewBatch,
    Location,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewCitation,
    ModelSurfaceReviewEvidenceObservation,
    ModelSurfaceReviewReachability,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
)


def _surface_id(seed: str) -> str:
    return f"model-surface:{hashlib.sha256(seed.encode()).hexdigest()}"


def _record(
    surface_id: str,
    *,
    role: str = "specialist:accounting_invariant",
    status: ModelSurfaceReviewStatus = ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
) -> ModelSurfaceReviewRecord:
    citation = ModelSurfaceReviewCitation(
        location=Location(
            path="src/SyntheticVault.sol",
            start_line=10,
            end_line=14,
            symbol="deposit",
            content_hash="a" * 64,
        ),
        symbol="deposit",
    )
    return ModelSurfaceReviewRecord(
        surface_id=surface_id,
        contract="SyntheticVault",
        function_or_state_surface="deposit(uint256)",
        review_role=role,
        status=status,
        rationale="Observed accounting is reconciled against the supplied balance.",
        citation=citation,
        invariant_considered="Recorded assets cannot exceed observed token receipts.",
        evidence_observations=(
            ModelSurfaceReviewEvidenceObservation(
                citation=citation,
                observed_behavior="The deposit path records the observed token receipt.",
                security_relevance="The recorded amount is bounded by the observed balance change.",
            ),
        ),
        reachability=ModelSurfaceReviewReachability(
            entry_point=citation,
            path=(citation,),
            actor_or_caller="external depositor",
            preconditions=("the token transfer returns successfully",),
        ),
        assumptions=("token balance observation is authoritative",),
        confidence=0.91,
    )


def _request(
    seed: str,
    *,
    subject_id: str | None = None,
    allowed_symbol: str = "deposit",
) -> ModelSurfaceReviewRequest:
    resolved_subject_id = subject_id or f"entity:{seed}"
    kind = ModelReviewSurfaceKind.ASSET_FUNCTION
    return ModelSurfaceReviewRequest(
        surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
            kind,
            resolved_subject_id,
        ),
        kind=kind,
        subject_id=resolved_subject_id,
        contract="SyntheticVault",
        function_or_state_surface="deposit(uint256)",
        critical=True,
        allowed_locations=(
            Location(
                path="src/SyntheticVault.sol",
                start_line=10,
                end_line=14,
                symbol=allowed_symbol,
                content_hash="a" * 64,
            ),
        ),
        allowed_symbols=(allowed_symbol,),
        invariant_considered="Recorded assets cannot exceed observed token receipts.",
    )


def _artifact_payload(
    records: tuple[ModelSurfaceReviewRecord, ...],
    requests: tuple[ModelSurfaceReviewRequest, ...] | None = None,
) -> dict[str, object]:
    surface_ids = tuple(record.surface_id for record in records)
    resolved_requests = requests or tuple(
        _request(surface_id, subject_id=f"record:{surface_id}") for surface_id in surface_ids
    )
    return {
        "schema_version": "1.0",
        "request_id": "request-synthetic-review",
        "review_role": "specialist:accounting_invariant",
        "requested_surface_ids": list(surface_ids),
        "requested_surface_ids_sha256": hashlib.sha256(
            json.dumps(
                list(surface_ids),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest(),
        "requested_surface_manifest_sha256": (
            ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(
                resolved_requests
            )
        ),
        "rendered_context_sha256": "0" * 64,
        "prompt_sha256": "1" * 64,
        "response_sha256": "2" * 64,
        "validated_response_sha256": "3" * 64,
        "response_schema_sha256": "4" * 64,
        "records": [record.model_dump(mode="json") for record in records],
    }


def _artifact(
    records: tuple[ModelSurfaceReviewRecord, ...],
    requests: tuple[ModelSurfaceReviewRequest, ...] | None = None,
) -> ModelSurfaceReviewArtifact:
    payload = _artifact_payload(records, requests)
    return ModelSurfaceReviewArtifact.model_validate(
        {
            **payload,
            "artifact_sha256": ModelSurfaceReviewArtifact.calculate_artifact_sha256(payload),
        }
    )


def test_surface_review_request_has_stable_inventory_identity() -> None:
    request = _request("stable")

    assert request.surface_id == ModelSurfaceReviewRequest.calculate_surface_id(
        request.kind,
        request.subject_id,
    )
    assert ModelSurfaceReviewRequest.model_validate_json(request.model_dump_json()) == request

    payload = request.model_dump(mode="json")
    payload["critical"] = False
    assert ModelSurfaceReviewRequest.model_validate(payload).surface_id == request.surface_id


def test_surface_review_request_rejects_inconsistent_or_uncitable_descriptor() -> None:
    payload = _request("invalid").model_dump(mode="json")
    payload["surface_id"] = _surface_id("wrong")
    with pytest.raises(ValidationError, match="inconsistent stable ID"):
        ModelSurfaceReviewRequest.model_validate(payload)

    payload = _request("uncitable").model_dump(mode="json")
    payload["allowed_locations"] = []
    payload["allowed_symbols"] = []
    with pytest.raises(ValidationError, match="requires an allowed location or symbol"):
        ModelSurfaceReviewRequest.model_validate(payload)


def test_candidate_review_batch_requires_sorted_unique_exact_surface_records() -> None:
    first = _record(_surface_id("first"))
    second = _record(_surface_id("second"))
    records = tuple(sorted((first, second), key=lambda record: record.surface_id))
    batch = CandidateReviewBatch(findings=[], surface_reviews=records)

    assert batch.require_exact_surface_set(tuple(record.surface_id for record in records)) is batch

    with pytest.raises(ValueError, match="exactly cover"):
        batch.require_exact_surface_set((records[0].surface_id,))
    with pytest.raises(ValidationError, match="unique and sorted"):
        CandidateReviewBatch(findings=[], surface_reviews=tuple(reversed(records)))
    with pytest.raises(ValidationError, match="surface_reviews"):
        CandidateReviewBatch.model_validate({"findings": []})


@pytest.mark.parametrize("status", list(ModelSurfaceReviewStatus))
def test_surface_review_record_supports_every_explicit_status(
    status: ModelSurfaceReviewStatus,
) -> None:
    record = _record(_surface_id(status.value), status=status)

    assert record.status.value == status.name
    assert record.citation.location is not None
    assert record.citation.symbol == "deposit"
    assert ModelSurfaceReviewRecord.model_validate_json(record.model_dump_json()) == record


def test_surface_review_record_requires_a_location_or_symbol() -> None:
    with pytest.raises(
        ValidationError,
        match="requires a source location or symbol",
    ):
        ModelSurfaceReviewCitation(location=None, symbol=None)


def test_surface_review_record_rejects_conflicting_citation_symbols() -> None:
    with pytest.raises(ValidationError, match="citation symbols disagree"):
        ModelSurfaceReviewCitation(
            location=Location(
                path="src/SyntheticVault.sol",
                start_line=10,
                end_line=10,
                symbol="deposit",
            ),
            symbol="withdraw",
        )


@pytest.mark.parametrize(
    ("update", "message"),
    [
        ({"surface_id": "surface-not-stable"}, "surface_id"),
        ({"rationale": "short"}, "at least 8 characters"),
        (
            {"assumptions": ("same", "same")},
            "assumptions must be bounded, unique, and sorted",
        ),
        (
            {"assumptions": ("z assumption", "a assumption")},
            "assumptions must be bounded, unique, and sorted",
        ),
        ({"confidence": 1.01}, "less than or equal to 1"),
    ],
)
def test_surface_review_record_rejects_invalid_shapes(
    update: dict[str, object],
    message: str,
) -> None:
    payload = _record(_surface_id("shape")).model_dump(mode="json")
    payload.update(update)

    with pytest.raises(ValidationError, match=message):
        ModelSurfaceReviewRecord.model_validate(payload)


def test_surface_review_record_requires_explicit_assumptions_field() -> None:
    payload = _record(_surface_id("assumptions-required")).model_dump(mode="json")
    del payload["assumptions"]

    with pytest.raises(ValidationError, match="assumptions"):
        ModelSurfaceReviewRecord.model_validate(payload)


def test_creditable_surface_review_rejects_generic_boilerplate_without_evidence() -> None:
    payload = _record(_surface_id("generic-boilerplate")).model_dump(mode="json")
    payload["rationale"] = "Reviewed."
    payload["evidence_observations"] = []
    payload["reachability"] = None

    with pytest.raises(
        ValidationError,
        match="requires explicit evidence and reachability",
    ):
        ModelSurfaceReviewRecord.model_validate(payload)


def test_creditable_surface_review_requires_evidence_bound_to_cited_surface() -> None:
    payload = _record(_surface_id("evidence-binding")).model_dump(mode="json")
    payload["evidence_observations"][0]["citation"] = {
        "location": None,
        "symbol": "unrelatedSurface",
    }

    with pytest.raises(
        ValidationError,
        match="observations must cite the reviewed surface",
    ):
        ModelSurfaceReviewRecord.model_validate(payload)


def test_surface_review_artifact_is_exact_set_role_and_hash_bound() -> None:
    records = tuple(
        sorted(
            (
                _record(_surface_id("state")),
                _record(_surface_id("function")),
            ),
            key=lambda record: record.surface_id,
        )
    )

    requests = tuple(
        _request(f"artifact-{index}", subject_id=f"record:{record.surface_id}")
        for index, record in enumerate(records)
    )
    requests = tuple(sorted(requests, key=lambda request: request.surface_id))
    remapped_records = tuple(
        record.model_copy(update={"surface_id": request.surface_id})
        for request, record in zip(requests, records, strict=True)
    )
    artifact = _artifact(remapped_records, requests)

    assert tuple(record.surface_id for record in artifact.records) == (
        artifact.requested_surface_ids
    )
    assert artifact.require_exact_requested_surface_manifest(requests) is artifact
    assert ModelSurfaceReviewArtifact.model_validate_json(artifact.model_dump_json()) == artifact


def test_surface_review_artifact_manifest_hash_binds_full_descriptors() -> None:
    request = _request("manifest")
    record = _record(request.surface_id)
    artifact = _artifact((record,), (request,))
    changed_request = request.model_copy(update={"critical": False})

    assert (
        artifact.requested_surface_manifest_sha256
        == ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256((request,))
    )
    with pytest.raises(ValueError, match="requested surface manifest"):
        artifact.require_exact_requested_surface_manifest((changed_request,))


def test_surface_review_artifact_rejects_duplicate_or_missing_records() -> None:
    record = _record(_surface_id("duplicate"))
    duplicate_payload = _artifact_payload((record, record))
    duplicate_payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(
        duplicate_payload
    )
    with pytest.raises(ValidationError, match="valid, unique, and sorted"):
        ModelSurfaceReviewArtifact.model_validate(duplicate_payload)

    other = _record(_surface_id("missing"))
    missing_payload = _artifact_payload(
        tuple(sorted((record, other), key=lambda item: item.surface_id))
    )
    missing_payload["records"] = [record.model_dump(mode="json")]
    missing_payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(
        missing_payload
    )
    with pytest.raises(ValidationError, match="exactly cover"):
        ModelSurfaceReviewArtifact.model_validate(missing_payload)


def test_surface_review_artifact_rejects_role_and_hash_tampering() -> None:
    record = _record(_surface_id("tamper"))
    wrong_role_payload = _artifact_payload((record,))
    wrong_role_payload["review_role"] = "source_audit"
    wrong_role_payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(
        wrong_role_payload
    )
    with pytest.raises(ValidationError, match="role differs"):
        ModelSurfaceReviewArtifact.model_validate(wrong_role_payload)

    artifact = _artifact((record,))
    tampered = artifact.model_dump(mode="json")
    tampered["response_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="artifact hash is inconsistent"):
        ModelSurfaceReviewArtifact.model_validate(tampered)


def test_surface_review_artifact_rejects_surface_set_hash_tampering() -> None:
    record = _record(_surface_id("surface-set-hash"))
    payload = _artifact_payload((record,))
    payload["requested_surface_ids_sha256"] = "f" * 64
    payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(payload)

    with pytest.raises(ValidationError, match="surface ID hash is inconsistent"):
        ModelSurfaceReviewArtifact.model_validate(payload)


def test_surface_review_artifact_rejects_unknown_fields() -> None:
    record = _record(_surface_id("extra"))
    payload = {
        **_artifact((record,)).model_dump(mode="json"),
        "generic_summary": "must not receive per-surface review credit",
    }

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ModelSurfaceReviewArtifact.model_validate(payload)
