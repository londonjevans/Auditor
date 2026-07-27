from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    Location,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewCitation,
    ModelSurfaceReviewRecord,
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
    return ModelSurfaceReviewRecord(
        surface_id=surface_id,
        contract="SyntheticVault",
        function_or_state_surface="deposit(uint256)",
        review_role=role,
        status=status,
        rationale="Observed accounting is reconciled against the supplied balance.",
        citation=ModelSurfaceReviewCitation(
            location=Location(
                path="src/SyntheticVault.sol",
                start_line=10,
                end_line=14,
                symbol="deposit",
                content_hash="a" * 64,
            ),
            symbol="deposit",
        ),
        invariant_considered="Recorded assets cannot exceed observed token receipts.",
        assumptions=("token balance observation is authoritative",),
        confidence=0.91,
    )


def _artifact_payload(
    records: tuple[ModelSurfaceReviewRecord, ...],
) -> dict[str, object]:
    surface_ids = tuple(record.surface_id for record in records)
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
        "prompt_sha256": "1" * 64,
        "response_sha256": "2" * 64,
        "validated_response_sha256": "3" * 64,
        "response_schema_sha256": "4" * 64,
        "records": [record.model_dump(mode="json") for record in records],
    }


def _artifact(
    records: tuple[ModelSurfaceReviewRecord, ...],
) -> ModelSurfaceReviewArtifact:
    payload = _artifact_payload(records)
    return ModelSurfaceReviewArtifact.model_validate(
        {
            **payload,
            "artifact_sha256": ModelSurfaceReviewArtifact.calculate_artifact_sha256(payload),
        }
    )


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

    artifact = _artifact(records)

    assert tuple(record.surface_id for record in artifact.records) == (
        artifact.requested_surface_ids
    )
    assert ModelSurfaceReviewArtifact.model_validate_json(artifact.model_dump_json()) == artifact


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
