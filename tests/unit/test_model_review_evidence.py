from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from mmaudit.models.openrouter import StructuredCompletion, strict_json_schema
from mmaudit.models.schemas import (
    CandidateReviewBatch,
    ContextExcerpt,
    ContextPackage,
    ExecutionEvidenceKind,
    Location,
    ModelRequestValidationStatus,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewCitation,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    RepositoryMap,
    UsageRecord,
)
from mmaudit.orchestration.model_review_evidence import (
    ModelReviewEvidenceError,
    seal_model_surface_review_artifact,
    validate_model_surface_review_record,
)

_ROLE = "specialist:accounting_invariant"
_PATH = "src/SyntheticVault.sol"
_SOURCE = (
    "contract SyntheticVault {\n"
    "    uint256 public totalAssets;\n"
    "    function deposit(uint256 assets) external {}\n"
    "}\n"
)
_INVARIANT = "Recorded assets cannot exceed observed token receipts."


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _location() -> Location:
    source_line = _SOURCE.splitlines(keepends=True)[2]
    return Location(
        path=_PATH,
        start_line=3,
        end_line=3,
        symbol="deposit(uint256)",
        content_hash=hashlib.sha256(source_line.encode()).hexdigest(),
    )


def _request(seed: str = "deposit") -> ModelSurfaceReviewRequest:
    subject_id = f"function:SyntheticVault:{seed}"
    return ModelSurfaceReviewRequest(
        surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
            ModelReviewSurfaceKind.ASSET_FUNCTION,
            subject_id,
        ),
        kind=ModelReviewSurfaceKind.ASSET_FUNCTION,
        subject_id=subject_id,
        contract="SyntheticVault",
        function_or_state_surface="deposit(uint256)",
        critical=True,
        allowed_locations=(_location(),),
        allowed_symbols=("deposit(uint256)",),
        invariant_considered=_INVARIANT,
    )


def _record(
    request: ModelSurfaceReviewRequest,
    *,
    role: str = _ROLE,
) -> ModelSurfaceReviewRecord:
    return ModelSurfaceReviewRecord(
        surface_id=request.surface_id,
        contract=request.contract,
        function_or_state_surface=request.function_or_state_surface,
        review_role=role,
        status=ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
        rationale="The supplied accounting path preserves the stated invariant.",
        citation=ModelSurfaceReviewCitation(
            location=request.allowed_locations[0],
            symbol=request.allowed_symbols[0],
        ),
        invariant_considered=request.invariant_considered,
        assumptions=("observed token receipts are authoritative",),
        confidence=0.91,
    )


def _repository_map() -> RepositoryMap:
    return RepositoryMap(
        root_name="synthetic",
        languages={"Solidity": 1},
        frameworks=[],
        manifests=[],
        entry_points=[],
        api_surfaces=[],
        auth_components=[],
        data_layers=[],
        network_clients=[],
        file_handlers=[],
        configuration_files=[],
        sensitive_processing=[],
        security_tests=[],
        files=[],
    )


def _context(
    requests: tuple[ModelSurfaceReviewRequest, ...],
    *,
    role: str = _ROLE,
) -> ContextPackage:
    return ContextPackage(
        role=role,
        byte_budget=100_000,
        bytes_used=len(_SOURCE.encode()),
        repository_map=_repository_map(),
        scanner_findings=[],
        excerpts=[
            ContextExcerpt(
                path=_PATH,
                start_line=1,
                end_line=4,
                content_hash=hashlib.sha256(_SOURCE.encode()).hexdigest(),
                content=_SOURCE,
            )
        ],
        requested_model_surfaces=list(requests),
    )


def _usage(batch: CandidateReviewBatch, *, role: str = _ROLE) -> UsageRecord:
    started_at = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
    ended_at = started_at + timedelta(milliseconds=125)
    generation_id = "generation-surface-review"
    endpoint = "approved-provider"
    schema_sha256 = _canonical_sha256(strict_json_schema(CandidateReviewBatch))
    return UsageRecord(
        request_id="request-surface-review",
        role=role,
        execution_evidence=ExecutionEvidenceKind.MOCK,
        requested_model="author/exact-model",
        returned_model="author/exact-model",
        actual_model="author/exact-model",
        provider="Approved Provider",
        model_family="author",
        timestamp=started_at,
        prompt_tokens=100,
        completion_tokens=25,
        total_tokens=125,
        reported_cost_usd=0.01,
        accounted_cost_usd=0.01,
        routing={
            "generation_id": generation_id,
            "selected_model": "author/exact-model",
            "selected_provider_endpoint": endpoint,
            "router_strategy": "direct",
            "finish_reason": "stop",
            "schema_sha256": schema_sha256,
            "router_metadata_sha256": "a" * 64,
            "provider_policy_sha256": "b" * 64,
            "validation_status": "valid",
            "zdr_requested": True,
            "data_collection": "deny",
            "repair_used": False,
            "repair_request": False,
            "request_started_at": started_at.isoformat(),
            "request_ended_at": ended_at.isoformat(),
            "latency_ms": 125,
            "certification_request": False,
        },
        prompt_sha256="c" * 64,
        response_sha256="d" * 64,
        validated_response_sha256=_canonical_sha256(batch.model_dump(mode="json")),
        request_body_sha256="e" * 64,
        schema_sha256=schema_sha256,
        openrouter_generation_id=generation_id,
        configured_provider_endpoints=[endpoint],
        actual_provider_endpoint=endpoint,
        started_at=started_at,
        ended_at=ended_at,
        latency_ms=125,
        finish_reason="stop",
        retry_count=0,
        validation_status=ModelRequestValidationStatus.VALID,
        status="success",
        attempts=1,
    )


def _completion(
    batch: CandidateReviewBatch,
    *,
    role: str = _ROLE,
) -> StructuredCompletion[CandidateReviewBatch]:
    return StructuredCompletion(value=batch, usage_record=_usage(batch, role=role))


def test_seal_surface_review_artifact_binds_exact_request_response_and_source() -> None:
    request = _request()
    record = _record(request)
    batch = CandidateReviewBatch(findings=[], surface_reviews=(record,))
    context = _context((request,))

    first = seal_model_surface_review_artifact(context, _completion(batch))
    second = seal_model_surface_review_artifact(context, _completion(batch))

    assert first is not None
    assert second is not None
    assert first == second
    assert first.request_id == "request-surface-review"
    assert first.requested_surface_ids == (request.surface_id,)
    assert first.records == (record,)
    assert first.require_exact_requested_surface_manifest((request,)) == first


def test_seal_accepts_an_exact_allowed_symbol_without_a_location() -> None:
    request = _request()
    record = _record(request).model_copy(
        update={
            "citation": ModelSurfaceReviewCitation(
                location=None,
                symbol="deposit(uint256)",
            )
        }
    )
    batch = CandidateReviewBatch(findings=[], surface_reviews=(record,))
    context = _context((request,)).model_copy(update={"excerpts": []})

    artifact = seal_model_surface_review_artifact(context, _completion(batch))

    assert artifact is not None
    assert artifact.records[0].citation.location is None


def test_empty_surface_request_returns_none_only_for_an_empty_surface_response() -> None:
    empty = CandidateReviewBatch(findings=[], surface_reviews=())

    assert seal_model_surface_review_artifact(_context(()), _completion(empty)) is None

    request = _request()
    nonempty = CandidateReviewBatch(findings=[], surface_reviews=(_record(request),))
    with pytest.raises(ModelReviewEvidenceError, match="exactly cover"):
        seal_model_surface_review_artifact(_context(()), _completion(nonempty))


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("contract", "OtherVault", "contract is inconsistent"),
        (
            "function_or_state_surface",
            "withdraw(uint256)",
            "function or state metadata is inconsistent",
        ),
        ("review_role", "source_audit", "review role is inconsistent"),
        ("invariant_considered", "A different invariant.", "invariant metadata is inconsistent"),
    ],
)
def test_seal_rejects_inconsistent_record_metadata(
    field: str,
    replacement: str,
    message: str,
) -> None:
    request = _request()
    record = _record(request).model_copy(update={field: replacement})
    batch = CandidateReviewBatch(findings=[], surface_reviews=(record,))

    with pytest.raises(ModelReviewEvidenceError, match=message):
        seal_model_surface_review_artifact(_context((request,)), _completion(batch))


def test_public_record_validation_rejects_a_different_surface_id() -> None:
    request = _request()
    record = _record(request).model_copy(update={"surface_id": _request("other").surface_id})

    with pytest.raises(ModelReviewEvidenceError, match="record ID"):
        validate_model_surface_review_record(request, record, _ROLE)


@pytest.mark.parametrize(
    ("location_update", "message"),
    [
        ({"path": "src/Other.sol"}, "unrequested source location"),
        ({"start_line": 2, "end_line": 3}, "unrequested source location"),
        ({"content_hash": "f" * 64}, "unrequested source location"),
        ({"symbol": "withdraw(uint256)"}, "unrequested source location"),
        ({"content_hash": None}, "lacks an exact source hash"),
    ],
)
def test_seal_rejects_wrong_location_descriptor(
    location_update: dict[str, object],
    message: str,
) -> None:
    request = _request()
    location = request.allowed_locations[0].model_copy(update=location_update)
    record = _record(request).model_copy(
        update={
            "citation": ModelSurfaceReviewCitation.model_construct(
                location=location,
                symbol=None,
            )
        }
    )
    batch = CandidateReviewBatch(findings=[], surface_reviews=(record,))

    with pytest.raises(ModelReviewEvidenceError, match=message):
        seal_model_surface_review_artifact(_context((request,)), _completion(batch))


def test_seal_rejects_an_unrequested_symbol() -> None:
    request = _request()
    record = _record(request).model_copy(
        update={
            "citation": ModelSurfaceReviewCitation(
                location=None,
                symbol="withdraw(uint256)",
            )
        }
    )
    batch = CandidateReviewBatch(findings=[], surface_reviews=(record,))

    with pytest.raises(ModelReviewEvidenceError, match="unrequested symbol"):
        seal_model_surface_review_artifact(_context((request,)), _completion(batch))


def test_seal_rejects_location_not_proven_by_the_supplied_source_context() -> None:
    request = _request()
    record = _record(request)
    batch = CandidateReviewBatch(findings=[], surface_reviews=(record,))
    context = _context((request,))
    poisoned_excerpt = context.excerpts[0].model_copy(
        update={"content": _SOURCE.replace("deposit", "withdraw")}
    )
    context = context.model_copy(update={"excerpts": [poisoned_excerpt]})

    with pytest.raises(ModelReviewEvidenceError, match="not proven by context"):
        seal_model_surface_review_artifact(context, _completion(batch))


def test_seal_rejects_missing_extra_and_duplicate_surface_records() -> None:
    first_request = _request()
    second_request = _request("second")
    first_record = _record(first_request)
    second_record = _record(second_request)

    missing = CandidateReviewBatch(findings=[], surface_reviews=())
    with pytest.raises(ModelReviewEvidenceError, match="exactly cover"):
        seal_model_surface_review_artifact(
            _context((first_request,)),
            _completion(missing),
        )

    records = tuple(sorted((first_record, second_record), key=lambda item: item.surface_id))
    extra = CandidateReviewBatch(findings=[], surface_reviews=records)
    with pytest.raises(ModelReviewEvidenceError, match="exactly cover"):
        seal_model_surface_review_artifact(
            _context((first_request,)),
            _completion(extra),
        )

    duplicate = CandidateReviewBatch.model_construct(
        findings=[],
        surface_reviews=(first_record, first_record),
    )
    with pytest.raises(ModelReviewEvidenceError, match="unique and sorted"):
        seal_model_surface_review_artifact(
            _context((first_request,)),
            _completion(duplicate),
        )


def test_seal_rejects_an_unsorted_requested_surface_manifest() -> None:
    requests = tuple(sorted((_request(), _request("second")), key=lambda item: item.surface_id))
    records = tuple(_record(request) for request in requests)
    batch = CandidateReviewBatch(findings=[], surface_reviews=records)
    context = _context(requests).model_copy(
        update={"requested_model_surfaces": list(reversed(requests))}
    )

    with pytest.raises(ModelReviewEvidenceError, match="unique and sorted"):
        seal_model_surface_review_artifact(context, _completion(batch))


def test_seal_rejects_non_investigator_or_mismatched_roles() -> None:
    request = _request()
    batch = CandidateReviewBatch(findings=[], surface_reviews=(_record(request),))

    with pytest.raises(ModelReviewEvidenceError, match="non-investigator"):
        seal_model_surface_review_artifact(
            _context((request,), role="threat_model"),
            _completion(batch, role="threat_model"),
        )
    with pytest.raises(ModelReviewEvidenceError, match="usage role differs"):
        seal_model_surface_review_artifact(
            _context((request,)),
            _completion(batch, role="source_audit"),
        )


def test_seal_rejects_incomplete_usage_and_response_or_schema_hash_mismatch() -> None:
    request = _request()
    batch = CandidateReviewBatch(findings=[], surface_reviews=(_record(request),))
    completion = _completion(batch)

    incomplete = StructuredCompletion(
        value=batch,
        usage_record=completion.usage_record.model_copy(update={"finish_reason": "length"}),
    )
    with pytest.raises(ModelReviewEvidenceError, match="completed creditable"):
        seal_model_surface_review_artifact(_context((request,)), incomplete)

    wrong_response = StructuredCompletion(
        value=batch,
        usage_record=completion.usage_record.model_copy(
            update={"validated_response_sha256": "f" * 64}
        ),
    )
    with pytest.raises(ModelReviewEvidenceError, match="response hash is inconsistent"):
        seal_model_surface_review_artifact(_context((request,)), wrong_response)

    wrong_schema_usage = completion.usage_record.model_copy(
        update={
            "schema_sha256": "f" * 64,
            "routing": {
                **completion.usage_record.routing,
                "schema_sha256": "f" * 64,
            },
        }
    )
    wrong_schema = StructuredCompletion(value=batch, usage_record=wrong_schema_usage)
    with pytest.raises(ModelReviewEvidenceError, match="schema hash is inconsistent"):
        seal_model_surface_review_artifact(_context((request,)), wrong_schema)
