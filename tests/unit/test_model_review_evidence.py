from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from mmaudit.models.openrouter import StructuredCompletion, strict_json_schema
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.schemas import (
    CandidateReviewBatch,
    ContextExcerpt,
    ContextPackage,
    ExecutionEvidenceKind,
    Location,
    ModelRequestValidationStatus,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewCitation,
    ModelSurfaceReviewEvidenceObservation,
    ModelSurfaceReviewReachability,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    RepositoryMap,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphSet,
    SolidityProvenance,
    SoliditySymbolIndex,
    UsageRecord,
)
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.model_review_evidence import (
    ModelReviewEvidenceError,
    validate_model_surface_review_record,
)
from mmaudit.orchestration.model_review_evidence import (
    seal_model_surface_review_artifact as _seal_model_surface_review_artifact,
)
from tests.identity_fixtures import synthetic_strict_zdr_privacy_routing
from tests.output_evidence_fixtures import (
    SYNTHETIC_OUTPUT_CAPABILITY_SHA256,
    synthetic_structured_output_routing,
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


def seal_model_surface_review_artifact(
    context: ContextPackage,
    completion: StructuredCompletion[CandidateReviewBatch],
) -> ModelSurfaceReviewArtifact | None:
    rendered_user_context = render_context(context)
    bound_completion = StructuredCompletion(
        value=completion.value,
        usage_record=completion.usage_record.model_copy(
            update={
                "user_prompt_sha256": hashlib.sha256(rendered_user_context.encode()).hexdigest()
            }
        ),
    )
    return _seal_model_surface_review_artifact(
        context,
        bound_completion,
        rendered_user_context=rendered_user_context,
    )


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


def _state_location() -> Location:
    source_line = _SOURCE.splitlines(keepends=True)[1]
    return Location(
        path=_PATH,
        start_line=2,
        end_line=2,
        symbol="totalAssets",
        content_hash=hashlib.sha256(source_line.encode()).hexdigest(),
    )


def _state_request() -> ModelSurfaceReviewRequest:
    subject_id = "state:SyntheticVault:totalAssets"
    return ModelSurfaceReviewRequest(
        surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
            ModelReviewSurfaceKind.STATE,
            subject_id,
        ),
        kind=ModelReviewSurfaceKind.STATE,
        subject_id=subject_id,
        contract="SyntheticVault",
        function_or_state_surface="totalAssets",
        critical=True,
        allowed_locations=(_state_location(),),
        allowed_symbols=("totalAssets",),
        invariant_considered=_INVARIANT,
    )


def _record(
    request: ModelSurfaceReviewRequest,
    *,
    role: str = _ROLE,
) -> ModelSurfaceReviewRecord:
    citation = ModelSurfaceReviewCitation(
        location=request.allowed_locations[0],
        symbol=request.allowed_symbols[0],
    )
    return ModelSurfaceReviewRecord(
        surface_id=request.surface_id,
        contract=request.contract,
        function_or_state_surface=request.function_or_state_surface,
        review_role=role,
        status=ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
        rationale="The supplied accounting path preserves the stated invariant.",
        citation=citation,
        invariant_considered=request.invariant_considered,
        evidence_observations=(
            ModelSurfaceReviewEvidenceObservation(
                citation=citation,
                observed_behavior="The deposit transition records the supplied receipt amount.",
                security_relevance=(
                    "deposit keeps observed assets bounded by the declared asset invariant."
                ),
            ),
        ),
        reachability=ModelSurfaceReviewReachability(
            entry_point=citation,
            path=(citation,),
            actor_or_caller="external depositor",
            preconditions=("the deposit call reaches the cited transition",),
        ),
        assumptions=("observed token receipts are authoritative",),
        confidence=0.91,
    )


def _state_record(request: ModelSurfaceReviewRequest) -> ModelSurfaceReviewRecord:
    state_citation = ModelSurfaceReviewCitation(
        location=request.allowed_locations[0],
        symbol="totalAssets",
    )
    entry_citation = ModelSurfaceReviewCitation(
        location=_location(),
        symbol="deposit(uint256)",
    )
    return ModelSurfaceReviewRecord(
        surface_id=request.surface_id,
        contract=request.contract,
        function_or_state_surface=request.function_or_state_surface,
        review_role=_ROLE,
        status=ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
        rationale="The external deposit path writes the accounting state.",
        citation=state_citation,
        invariant_considered=request.invariant_considered,
        evidence_observations=(
            ModelSurfaceReviewEvidenceObservation(
                citation=state_citation,
                observed_behavior="deposit writes totalAssets after observing the receipt.",
                security_relevance="The totalAssets write preserves the observed asset invariant.",
            ),
        ),
        reachability=ModelSurfaceReviewReachability(
            entry_point=entry_citation,
            path=(entry_citation, state_citation),
            actor_or_caller="external depositor",
            preconditions=("deposit reaches its accounting write",),
        ),
        assumptions=("the compiler graph represents the local state write",),
        confidence=0.92,
    )


def _state_context(
    request: ModelSurfaceReviewRequest,
    *,
    include_edge: bool = True,
) -> ContextPackage:
    entry = _context((request,)).solidity_index
    assert entry is not None
    state_entity = SolidityEntity(
        id=request.subject_id,
        kind=SolidityEntityKind.STATE_VARIABLE,
        name="totalAssets",
        contract_name="SyntheticVault",
        path=_PATH,
        start_line=2,
        end_line=2,
        byte_start=0,
        byte_end=len(_SOURCE.encode()),
        source_hash=_state_location().content_hash or "0" * 64,
        provenance=SolidityProvenance.COMPILER,
        confidence=1,
        transformation="synthetic_model_review_evidence",
    )
    index = entry.model_copy(update={"entities": [*entry.entities, state_entity]})
    edges = (
        [
            SolidityGraphEdge(
                graph=SolidityGraphKind.STATE_WRITE,
                source_id="function:SyntheticVault:deposit",
                target_id=request.subject_id,
                label="writes totalAssets",
                provenance=SolidityProvenance.COMPILER,
                path=_PATH,
                start_line=3,
                end_line=3,
                source_hash=_location().content_hash or "0" * 64,
                confidence=1,
                transformation="synthetic_model_review_evidence",
            )
        ]
        if include_edge
        else []
    )
    return _context(
        (request,),
        index=index,
        graphs=SolidityGraphSet(edges=edges),
    )


def _record_with_citation(
    record: ModelSurfaceReviewRecord,
    citation: ModelSurfaceReviewCitation,
) -> ModelSurfaceReviewRecord:
    assert record.reachability is not None
    observations = tuple(
        observation.model_copy(update={"citation": citation})
        for observation in record.evidence_observations
    )
    reachability = record.reachability.model_copy(
        update={
            "entry_point": citation,
            "path": (citation,),
        }
    )
    return record.model_copy(
        update={
            "citation": citation,
            "evidence_observations": observations,
            "reachability": reachability,
        }
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
    index: SoliditySymbolIndex | None = None,
    graphs: SolidityGraphSet | None = None,
) -> ContextPackage:
    resolved_index = index or SoliditySymbolIndex(
        projects=[],
        entities=[
            SolidityEntity(
                id="function:SyntheticVault:deposit",
                kind=SolidityEntityKind.FUNCTION,
                name="deposit",
                contract_name="SyntheticVault",
                path=_PATH,
                start_line=3,
                end_line=3,
                byte_start=0,
                byte_end=len(_SOURCE.encode()),
                source_hash=_location().content_hash or "0" * 64,
                provenance=SolidityProvenance.COMPILER,
                confidence=1,
                transformation="synthetic_model_review_evidence",
                visibility="external",
                signature="deposit(uint256)",
            )
        ],
        ast_sources=[_PATH],
    )
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
        solidity_index=resolved_index,
        solidity_graphs=graphs or SolidityGraphSet(edges=[]),
    )


def _usage(batch: CandidateReviewBatch, *, role: str = _ROLE) -> UsageRecord:
    started_at = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
    ended_at = started_at + timedelta(milliseconds=125)
    generation_id = "generation-surface-review"
    endpoint = "approved-provider"
    schema_sha256 = _canonical_sha256(strict_json_schema(CandidateReviewBatch))
    prompt_sha256 = "c" * 64
    response_sha256 = "d" * 64
    validated_response_sha256 = _canonical_sha256(batch.model_dump(mode="json"))
    request_body_sha256 = "e" * 64
    endpoint_snapshot_sha256 = "f" * 64
    provider_policy_sha256 = "b" * 64
    routing = synthetic_strict_zdr_privacy_routing(
        {
            "generation_id": generation_id,
            "selected_model": "author/exact-model",
            "selected_provider_endpoint": endpoint,
            "router_strategy": "direct",
            "finish_reason": "stop",
            "schema_sha256": schema_sha256,
            "router_metadata_sha256": "a" * 64,
            "provider_policy_sha256": provider_policy_sha256,
            "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
            "output_capability_sha256": SYNTHETIC_OUTPUT_CAPABILITY_SHA256,
            "validation_status": "valid",
            "zdr_requested": True,
            "data_collection": "deny",
            "repair_used": False,
            "repair_request": False,
            "structured_output": synthetic_structured_output_routing(
                configured_provider_endpoints=(endpoint,),
                selected_provider_endpoint=endpoint,
                endpoint_snapshot_sha256=endpoint_snapshot_sha256,
                prompt_sha256=prompt_sha256,
                request_body_sha256=request_body_sha256,
                provider_policy_sha256=provider_policy_sha256,
                schema_sha256=schema_sha256,
                original_response_sha256=response_sha256,
                validated_response_sha256=validated_response_sha256,
            ),
            "request_started_at": started_at.isoformat(),
            "request_ended_at": ended_at.isoformat(),
            "latency_ms": 125,
            "certification_request": False,
        },
        source_label=f"model-review-evidence:{role}",
    )
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
        routing=routing,
        prompt_sha256=prompt_sha256,
        response_sha256=response_sha256,
        validated_response_sha256=validated_response_sha256,
        request_body_sha256=request_body_sha256,
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


def _rebind_output_usage(
    record: UsageRecord,
    *,
    validated_response_sha256: str | None = None,
    schema_sha256: str | None = None,
) -> UsageRecord:
    structured = record.routing["structured_output"]
    next_validated = validated_response_sha256 or record.validated_response_sha256
    next_schema = schema_sha256 or record.schema_sha256
    assert next_validated is not None
    assert next_schema is not None
    assert record.actual_provider_endpoint is not None
    assert record.request_body_sha256 is not None
    assert record.response_sha256 is not None
    next_structured = synthetic_structured_output_routing(
        configured_provider_endpoints=tuple(record.configured_provider_endpoints),
        selected_provider_endpoint=record.actual_provider_endpoint,
        endpoint_snapshot_sha256=structured["endpoint_snapshot_sha256"],
        output_capability_sha256=structured["output_capability_sha256"],
        prompt_sha256=record.prompt_sha256,
        request_body_sha256=record.request_body_sha256,
        provider_policy_sha256=structured["provider_policy_sha256"],
        schema_sha256=next_schema,
        original_response_sha256=record.response_sha256,
        validated_response_sha256=next_validated,
        mode=StructuredOutputMode(structured["requested_mode"]),
    )
    return record.model_copy(
        update={
            "validated_response_sha256": next_validated,
            "schema_sha256": next_schema,
            "routing": {
                **record.routing,
                "schema_sha256": next_schema,
                "structured_output": next_structured,
            },
        }
    )


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
    assert (
        first.rendered_context_sha256
        == hashlib.sha256(render_context(context).encode()).hexdigest()
    )
    assert first.require_exact_requested_surface_manifest((request,)) == first


def test_seal_rejects_a_post_hoc_context_substitution() -> None:
    request = _request()
    record = _record(request)
    completion = _completion(CandidateReviewBatch(findings=[], surface_reviews=(record,)))
    original_context = _context((request,))
    frozen_rendering = render_context(original_context)
    bound_completion = StructuredCompletion(
        value=completion.value,
        usage_record=completion.usage_record.model_copy(
            update={"user_prompt_sha256": hashlib.sha256(frozen_rendering.encode()).hexdigest()}
        ),
    )
    substituted_context = original_context.model_copy(
        update={"omissions": ["post-hoc context substitution"]}
    )

    with pytest.raises(ModelReviewEvidenceError, match="differs from the rendered"):
        _seal_model_surface_review_artifact(
            substituted_context,
            bound_completion,
            rendered_user_context=frozen_rendering,
        )


def test_seal_credits_a_state_surface_only_with_a_known_adjacent_entry_path() -> None:
    request = _state_request()
    record = _state_record(request)
    batch = CandidateReviewBatch(findings=[], surface_reviews=(record,))

    artifact = seal_model_surface_review_artifact(
        _state_context(request),
        _completion(batch),
    )

    assert artifact is not None
    assert artifact.records == (record,)


def test_seal_rejects_a_state_surface_self_loop_or_non_adjacent_path() -> None:
    request = _state_request()
    valid = _state_record(request)
    state_citation = valid.citation
    assert valid.reachability is not None
    self_loop = valid.model_copy(
        update={
            "reachability": valid.reachability.model_copy(
                update={
                    "entry_point": state_citation,
                    "path": (state_citation,),
                }
            )
        }
    )
    with pytest.raises(ModelReviewEvidenceError, match="exact known"):
        seal_model_surface_review_artifact(
            _state_context(request),
            _completion(CandidateReviewBatch(findings=[], surface_reviews=(self_loop,))),
        )

    with pytest.raises(ModelReviewEvidenceError, match="not adjacent"):
        seal_model_surface_review_artifact(
            _state_context(request, include_edge=False),
            _completion(CandidateReviewBatch(findings=[], surface_reviews=(valid,))),
        )


def test_seal_rejects_generic_or_request_copied_observation_text() -> None:
    request = _request()
    valid = _record(request)
    generic_observation = valid.evidence_observations[0].model_copy(
        update={
            "observed_behavior": (
                "The synthetic source surface was inspected for its state effects."
            ),
            "security_relevance": (
                "Those effects determine whether the supplied invariant is preserved."
            ),
        }
    )
    generic = valid.model_copy(update={"evidence_observations": (generic_observation,)})
    with pytest.raises(ModelReviewEvidenceError, match="generic boilerplate"):
        seal_model_surface_review_artifact(
            _context((request,)),
            _completion(CandidateReviewBatch(findings=[], surface_reviews=(generic,))),
        )

    copied_observation = valid.evidence_observations[0].model_copy(
        update={
            "observed_behavior": request.invariant_considered,
            "security_relevance": request.invariant_considered,
        }
    )
    copied = valid.model_copy(update={"evidence_observations": (copied_observation,)})
    with pytest.raises(ModelReviewEvidenceError, match="copied request text"):
        seal_model_surface_review_artifact(
            _context((request,)),
            _completion(CandidateReviewBatch(findings=[], surface_reviews=(copied,))),
        )


def test_seal_rejects_a_location_and_symbol_that_resolve_to_different_surfaces() -> None:
    base = _request()
    location = base.allowed_locations[0].model_copy(update={"symbol": None})
    request = base.model_copy(
        update={
            "allowed_locations": (location,),
            "allowed_symbols": ("deposit(uint256)", "totalAssets"),
        }
    )
    mismatched = _record_with_citation(
        _record(base),
        ModelSurfaceReviewCitation(
            location=location,
            symbol="totalAssets",
        ),
    ).model_copy(
        update={
            "surface_id": request.surface_id,
            "contract": request.contract,
            "function_or_state_surface": request.function_or_state_surface,
            "invariant_considered": request.invariant_considered,
        }
    )
    state_context = _state_context(_state_request())
    assert state_context.solidity_index is not None

    with pytest.raises(ModelReviewEvidenceError, match="exact known"):
        seal_model_surface_review_artifact(
            _context((request,), index=state_context.solidity_index),
            _completion(CandidateReviewBatch(findings=[], surface_reviews=(mismatched,))),
        )


def test_seal_rejects_an_unresolved_non_inventory_surface_subject() -> None:
    base = _request()
    forged_subject = "function:SyntheticVault:not-indexed"
    request = base.model_copy(
        update={
            "subject_id": forged_subject,
            "surface_id": ModelSurfaceReviewRequest.calculate_surface_id(
                base.kind,
                forged_subject,
            ),
        }
    )
    record = _record(base).model_copy(update={"surface_id": request.surface_id})

    with pytest.raises(ModelReviewEvidenceError, match="exact deterministic surface"):
        seal_model_surface_review_artifact(
            _context((request,)),
            _completion(CandidateReviewBatch(findings=[], surface_reviews=(record,))),
        )


def test_seal_accepts_an_exact_allowed_symbol_with_source_bytes() -> None:
    request = _request()
    record = _record_with_citation(
        _record(request),
        ModelSurfaceReviewCitation(
            location=None,
            symbol="deposit(uint256)",
        ),
    )
    batch = CandidateReviewBatch(findings=[], surface_reviews=(record,))
    context = _context((request,))

    artifact = seal_model_surface_review_artifact(context, _completion(batch))

    assert artifact is not None
    assert artifact.records[0].citation.location is None


def test_seal_rejects_a_symbol_only_review_without_source_bytes() -> None:
    request = _request()
    record = _record_with_citation(
        _record(request),
        ModelSurfaceReviewCitation(location=None, symbol="deposit(uint256)"),
    )
    context = _context((request,)).model_copy(update={"excerpts": []})

    with pytest.raises(ModelReviewEvidenceError, match="source evidence was omitted"):
        seal_model_surface_review_artifact(
            context,
            _completion(CandidateReviewBatch(findings=[], surface_reviews=(record,))),
        )


def test_seal_rejects_a_known_location_without_source_bytes() -> None:
    request = _request()
    context = _context((request,)).model_copy(update={"excerpts": []})

    with pytest.raises(ModelReviewEvidenceError, match="source evidence was omitted"):
        seal_model_surface_review_artifact(
            context,
            _completion(CandidateReviewBatch(findings=[], surface_reviews=(_record(request),))),
        )


def test_seal_rejects_credit_when_preferred_source_was_omitted_by_budget() -> None:
    request = _request()
    context = _context((request,)).model_copy(
        update={
            "excerpts": [],
            "omissions": [f"{_PATH}: preferred source omitted by context budget"],
        }
    )

    with pytest.raises(ModelReviewEvidenceError, match="source evidence was omitted"):
        seal_model_surface_review_artifact(
            context,
            _completion(CandidateReviewBatch(findings=[], surface_reviews=(_record(request),))),
        )


def test_seal_allows_inconclusive_when_source_was_omitted_by_budget() -> None:
    request = _request()
    record = _record(request).model_copy(
        update={
            "status": ModelSurfaceReviewStatus.INCONCLUSIVE,
            "evidence_observations": (),
            "reachability": None,
        }
    )
    context = _context((request,)).model_copy(
        update={
            "excerpts": [],
            "omissions": [f"{_PATH}: preferred source omitted by context budget"],
        }
    )

    artifact = seal_model_surface_review_artifact(
        context,
        _completion(CandidateReviewBatch(findings=[], surface_reviews=(record,))),
    )

    assert artifact is not None
    assert artifact.records[0].status is ModelSurfaceReviewStatus.INCONCLUSIVE


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
    record = _record_with_citation(
        _record(request),
        ModelSurfaceReviewCitation.model_construct(
            location=location,
            symbol=None,
        ),
    )
    batch = CandidateReviewBatch(findings=[], surface_reviews=(record,))

    with pytest.raises(ModelReviewEvidenceError, match=message):
        seal_model_surface_review_artifact(_context((request,)), _completion(batch))


def test_seal_rejects_an_unrequested_symbol() -> None:
    request = _request()
    record = _record_with_citation(
        _record(request),
        ModelSurfaceReviewCitation(
            location=None,
            symbol="withdraw(uint256)",
        ),
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

    with pytest.raises(ModelReviewEvidenceError, match="not proven by supplied context bytes"):
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
        usage_record=_rebind_output_usage(
            completion.usage_record,
            validated_response_sha256="f" * 64,
        ),
    )
    with pytest.raises(ModelReviewEvidenceError, match="response hash is inconsistent"):
        seal_model_surface_review_artifact(_context((request,)), wrong_response)

    wrong_schema_usage = _rebind_output_usage(
        completion.usage_record,
        schema_sha256="f" * 64,
    )
    wrong_schema = StructuredCompletion(value=batch, usage_record=wrong_schema_usage)
    with pytest.raises(ModelReviewEvidenceError, match="schema hash is inconsistent"):
        seal_model_surface_review_artifact(_context((request,)), wrong_schema)
